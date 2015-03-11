--[[
  
  Copyright (C) 2014 Masatoshi Teruya

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
 
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
   
  lib/oauth2.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 14/12/11.
  
--]]

-- module
local typeof = require('util.typeof');
local createHttpClient = require('authnz.util').createHttpClient;
local encodeQuery = require('authnz.util').encodeQuery;
local genRandom = require('authnz.util').genRandom;

-- MARK: class OAuth2
-- constants
local OPTIONS = {
    -- oauth2 params
    clientId = {
        req = true,
        typ = 'string',
        msg = 'opts.clientId must be string'
    },
    secret = {
        req = true,
        typ = 'string',
        msg = 'opts.secret must be string'
    },
    redirectURI = {
        req = true,
        typ = 'string',
        msg = 'opts.redirectURI must be string'
    },
    authorizeURI = {
        req = true,
        typ = 'string',
        msg = 'opts.authorizeURI must be string'
    },
    tokenURI = {
        req = true,
        typ = 'string',
        msg = 'opts.tokenURI must be string'
    }
};

local OAuth2 = require('halo').class.OAuth2;


function OAuth2:__index( method )
    local own = protected( self );
    
    -- unsupported method
    if not typeof.Function( own.req[method] ) then
        return function()
            return nil, ('unsupported http method: %q'):format( method );
        end
    end
    
    
    return function( _, uri, query, body, opts )
        if type( opts ) ~= 'table' then
            opts = {
                header = {};
            };
        elseif type( opts.header ) ~= 'table' then
            opts.header = {};
        end
        -- set query and body
        opts.query = query;
        opts.body = body;
        -- set headers
        opts.header['Authorization'] = own.authHdrVal;
        opts.header["Content-Type"] = "application/json";
        opts.header["Accept"] = "application/json";
        
        return own.req[method]( own.req, uri, opts );
    end
end


function OAuth2:init( opts )
    local own = protected( self );
    local err;
    
    -- create http client
    own.req, err = createHttpClient( own, OPTIONS, opts );
    if err then
        return nil, err;
    end
    
    return self;
end


-- generate state value
function OAuth2:genState()
    return genRandom();
end


-- return boolean, err
function OAuth2:finalizeAuthQuery()
    return true;
end


function OAuth2:genAuthQuery( opts )
    local own = protected( self );
    local qry = {
        client_id       = own.clientId,
        redirect_uri    = own.redirectURI,
        response_type   = 'code',
        scope           = {},
        state           = self:genState()
    };
    local ok, err;
    
    opts = opts or {};
    if not typeof.table( opts ) then
        return nil, 'opts must be table';
    end
    
    -- check resposen_type: default code
    if opts.response_type ~= nil then
        if not typeof.string( opts.response_type ) then
            return nil, 'opts.response_type must be string';
        end
        qry.response_type = opts.response_type;
    end
    
    -- check scope
    if opts.scope == nil then
        opts.scope = {};
    elseif not typeof.table( opts.scope ) then
        return nil, 'opts.scope must be table';
    end
    -- set opts.scope
    for _, scope in ipairs( opts.scope ) do
        if not typeof.string( scope ) then
            return nil, ('opts.scope#%d must be string'):format( _ );
        end
        qry.scope[#qry.scope+1] = scope;
    end
    
    -- finalize
    ok, err = self:finalizeAuthQuery( qry, opts );
    if err then
        return nil, err;
    end
    
    qry.scope = #qry.scope > 0 and table.concat( qry.scope, ' ' ) or nil;
    return {
        state = qry.state,
        uri = own.authorizeURI .. '?' .. encodeQuery( qry )
    };
end



local function verifyResponse( self, res, err )
    -- request error
    if err then
        return nil, err;
    -- token error spec: 
    -- http://tools.ietf.org/html/rfc6749#section-5.2
    elseif res.status ~= 200 then
        err = {};
        for _, v in pairs( res.body ) do
            err[#err+1] = v;
        end
        
        return nil, table.concat( err, '\n' );
    end
    
    -- call method
    return self:verifyResponse( res );
end


-- query
--  state = state-value
--  error = access_denied
function OAuth2:authorize( qry, state )
    if not typeof.table( qry ) then
        return nil, 'qry must be table';
    -- check state
    elseif state ~= qry.state then
        return nil, 'invalid state token';
    -- check error
    elseif qry.error then
        return nil, qry.error;
    else
        local own = protected( self );
        -- token request
        -- spec: http://tools.ietf.org/html/rfc6749#section-4.1.3
        local res, err = verifyResponse( self, own.req:post( own.tokenURI, {
            header = {
                accept = 'application/json'
            },
            body = {
                client_id       = own.clientId,
                client_secret   = own.secret,
                redirect_uri    = own.redirectURI,
                grant_type      = 'authorization_code',
                code            = qry.code
            }
        }));
        
        
        -- request error
        if err then
            return nil, err;
        -- response spec
        -- http://tools.ietf.org/html/rfc6749#section-5.1
        -- update accessToken and refreshToken
        else
            own.accessToken = res.access_token;
            own.expiresIn = res.expires_in;
            own.tokenType = res.token_type;
            own.refreshToken = res.refresh_token;
            -- create authorization header value
            own.authHdrVal = own.tokenType .. ' ' .. own.accessToken;
        end
        
        return res, err;
    end
end


function OAuth2:refresh()
    local own = protected( self );
    local res, err = verifyResponse( self, own.req:post( own.tokenURI, {
        header = {
            accept          = 'application/json',
            authorization   = 'Bearer ' .. own.accessToken
        },
        query = {
            client_id       = own.clientId,
            client_secret   = own.secret,
            grant_type      = 'refresh_token',
            refresh_token   = own.refreshToken
        }
    }));
    
    -- request error
    if err then
        return nil, err;
    -- response spec
    -- http://tools.ietf.org/html/rfc6749#section-5.1
    -- update accessToken
    else
        own.accessToken = res.access_token;
        own.expiresIn = res.expires_in;
        own.tokenType = res.token_type;
        -- create authorization header value
        own.authHdrVal = own.tokenType .. ' ' .. own.accessToken;
    end
    
    return res, err;
end


function OAuth2:token()
    local own = protected( self );
    
    return {
        accessToken = own.accessToken,
        expiresIn = own.expiresIn,
        tokenType = own.tokenType,
        refreshToken = own.refreshToken
    };
end


function OAuth2:verifyResponse( res )
    return res.body;
end


return OAuth2.exports;
