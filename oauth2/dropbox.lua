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
  
  oauth2/dropbox.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 14/12/11.
  
--]]

-- module
local typeof = require('util.typeof');
local decodeJSON = require('cjson.safe').decode;
local keys = require('util.table').keys;
local concat = table.concat;
local DropboxCli = require('authnz.client.dropbox');
-- constants
local AUTHORIZE_URI = 'https://www.dropbox.com/1/oauth2/authorize';
local TOKEN_URI     = 'https://api.dropbox.com/1/oauth2/token';
local RESPONSE_TYPE = {
    code    = true,
    token   = true
};

-- class
local Dropbox = require('halo').class.Dropbox;


Dropbox.inherits {
    'authnz.oauth2.OAuth2'
};


function Dropbox:init( opts )
    opts = opts or {};
    if not typeof.table( opts ) then
        return nil, 'opts must be table';
    end
    opts.authorizeURI = AUTHORIZE_URI;
    opts.tokenURI = TOKEN_URI;
    
    return base['authnz.oauth2.OAuth2'].init( self, opts );
end


function Dropbox:createClient( token )
    return DropboxCli.new( protected(self).client, token );
end


function Dropbox:finalizeAuthQuery( qry, opts )
    -- check response_type
    if not RESPONSE_TYPE[qry.response_type] then
        return false, ('opts.response_type must be %s'):format(
            concat( keys( RESPONSE_TYPE ), ' | ' )
        );
    end
    -- set boolean values of force_reapprove and disable_signup
    for _, k in ipairs({ 'force_reapprove', 'disable_signup' }) do
        if opts[k] then
            if not typeof.boolean( opts[k] ) then
                return false, ('opts.%s must be boolean'):format( k );
            end
            qry[k] = opts[k];
        end
    end
    
    return true;
end


--
-- NOTE: dropbox oauth2 API does not set a "application/json" to a 
--       content-type header.
--
function Dropbox:verifyResponse( res )
    return decodeJSON( res.body );
end


return Dropbox.exports;
