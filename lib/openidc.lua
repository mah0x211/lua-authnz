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
   
  lib/openidc.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 14/12/10.
  
--]]

-- module
local typeof = require('util.typeof');
local date = require('date');
local jose = require('jose');
local createHttpClient = require('authnz.util').createHttpClient;
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
    -- optional
    discoveryURI = {
        req = true,
        typ = 'string',
        msg = 'opts.discoveryURI must be string'
    },
    tokenCheckURI = {
        typ = 'string',
        msg = 'opts.tokenCheckURI must be string'
    },
    -- require if discoveryURI is nil
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

local OpenIdc = require('halo').class.OpenIdc;


function OpenIdc:init( opts )
    local own = protected( self );
    local err;
    
    -- check discoveryURI
    if opts.discoveryURI == nil then
        OPTIONS.discoveryURI.req = false;
        OPTIONS.authorizeURI.req = true;
        OPTIONS.tokenURI.req = true;
    else
        OPTIONS.discoveryURI.req = true;
        OPTIONS.authorizeURI.req = false;
        OPTIONS.tokenURI.req = false;
    end
    
    -- create http client
    own.req, err = createHttpClient( own, OPTIONS, opts );
    if err then
        return nil, err;
    end
    
    return self;
end


function OpenIdc:discovery()
    local own = protected(self);
    
    if own.discoveryURI ~= nil and not own.discoveryTTL or 
       own.discoveryTTL < date(true) then
        local res, err = own.req:get( own.discoveryURI );
        local cfg = res.body;
        
        if err then
            return err;
        elseif res.status ~= 200 then
            err = {};
            for _, v in pairs( res.body ) do
                err[#err+1] = v;
            end
            return table.concat( err, '\n' );
        end
        own.discoveryTTL = date( res.header.EXPIRES );
        own.issuer = cfg.issuer;
        own.revokeURI = cfg.revocation_endpoint;
        own.authorizeURI = cfg.authorization_endpoint;
        own.tokenURI = cfg.token_endpoint;
        own.jwksURI = cfg.jwks_uri;
        -- save configuration
        own.config = cfg;
    end
end


-- generate state value
function OpenIdc:genState()
    return genRandom();
end


-- generate nonce value
function OpenIdc:genNonce()
    return genRandom();
end


-- return boolean, err
function OpenIdc:finalizeAuthQuery()
    return true;
end


function OpenIdc:genAuthQuery( opts )
    local err;
    
    opts = opts or {};
    if not typeof.table( opts ) then
        return nil, 'opts must be table';
    end
    
    -- check resposen_type: default code
    if opts.response_type == nil then
        opts.response_type = 'code';
    elseif not typeof.string( opts.response_type ) then
        return nil, 'opts.response_type must be string';
    end
    -- check scope
    if opts.scope == nil then
        opts.scope = {};
    elseif not typeof.table( opts.scope ) then
        return nil, 'opts.scope must be table';
    end
    
    err = self:discovery();
    if not err then
        local own = protected( self );
        local qry = {
            client_id       = own.clientId,
            redirect_uri    = own.redirectURI,
            -- default code flow
            response_type   = opts.response_type,
            scope           = { 'openid' },
            state           = self:genState(),
            nonce           = self:genNonce()
        };
        local ok;
        
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
        
        qry.scope = table.concat( qry.scope, ' ' );
        return {
            state = qry.state,
            uri = own.authorizeURI .. '?' .. encodeQuery( qry )
        };
    end
    
    return nil, err;
end


-- query
--  state = state-value
--  error = access_denied
function OpenIdc:authorize( qry, state )
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
        local err = self:discovery();
        local res;
        
        if err then
            return nil, err;
        end
        -- token request
        -- spec: http://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
        res, err = own.req:post( own.tokenURI, {
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
        -- http://openid.net/specs/openid-connect-core-1_0.html#TokenErrorResponse
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


function OpenIdc:verifyResponse( res )
    -- verify and docode id_token
    local err;
    
    res.body.id_token, err = self:verifyIdToken( res.body.id_token );
    if err then
        return nil, err;
    end
    
    return res.body;
end


-- return user_id, jwt, err
function OpenIdc:verifyIdToken( id_token )
    local own = protected(self);
    local jwt, err = jose.jwt.read( id_token );
    
    if err then
        return nil, err;
    -- aud must be same as clientId
    elseif jwt.claims.aud ~= own.clientId then
        return nil, 'invalid aud';
    -- iss must be same as own.issuer
    elseif jwt.claims.iss ~= own.issuer then
        return nil, 'invalid iss';
    -- alg: none
    elseif not jwt.data then
        return jwt;
    -- jwksURI undefined
    elseif type( own.jwksURI ) ~= 'string' then
        return nil, 'jwksURI undefined';
    else
        local kid = jwt.header.kid;
        local alg = jwt.header.alg;
        -- fetch JWK set
        local res, err = own.req:get( own.jwksURI );
        local jws, _;
        
        -- fetch error
        if err then
            return nil, err;
        -- return code is not 200
        elseif res.status ~= 200 then
            err = {};
            for _, v in pairs( res.body ) do
                err[#err+1] = v;
            end
            return nil, table.concat( err, '\n' );
        elseif type( res.body.keys ) ~= 'table' then
            return nil, 'invalid JWK set';
        end
        
        -- verify with JWK set
        for _, jwk in ipairs( res.body.keys ) do
            if alg == jwk.alg and ( not kid or kid == jwk.kid ) then
                jws, err = jose.jws.create( jwk );
                -- internal server error
                if err then
                    return nil, err;
                end
                
                _, err = jws:verify( jwt.data, jwt.sign );
                if err then
                    return nil, err;
                end
                
                return jwt;
            end
        end
        
        return nil, 'JWK not found';
    end
end


function OpenIdc:request( token, method, uri, opts )
    local own = protected(self);
    
    if type( opts ) ~= 'table' then
        opts = {
            header = {};
        };
    elseif type( opts.header ) ~= 'table' then
        opts.header = {};
    end
    opts.header['Authorization'] = token.token_type .. ' ' .. token.access_token;
    
    return own.req[method]( own.req, uri, opts );
end


return OpenIdc.exports;
