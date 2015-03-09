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
local createClient = require('authnz.util').createClient;
local encodeQuery = require('authnz.util').encodeQuery;
local genRandom = require('authnz.util').genRandom;

-- MARK: class OpenIdc
-- constants
local OPTIONS = {
    -- openid connect params
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


function OAuth2:init( opts )
    local own = protected( self );
    local err;
    
    -- create http client
    own.client, err = createClient( own, OPTIONS, opts );
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
        local res, err = own.client:post( own.tokenURI, {
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
        });
        
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
        
        return self:verifyResponse( res );
    end
end


function OAuth2:verifyResponse( res )
    return res.body;
end


return OAuth2.exports;
