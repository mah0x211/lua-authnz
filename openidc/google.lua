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
   
  social/google.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 14/12/10.
  
--]]

-- module
local keys = require('util.table').keys;
local concat = table.concat;
-- constants
local DISCOVERY_URI = 'https://accounts.google.com/.well-known/openid-configuration';
local TOKENCHECK_URI = 'https://www.googleapis.com/oauth2/v1/tokeninfo';
local ACCESS_TYPE = {
    online  = true,
    offline = true
};
local PROMPT = {
    none            = true,
    consent         = true,
    select_account  = true
};

-- class
local Google = require('halo').class.Google;

Google.inherits {
    'authnz.openidc.OpenIdc'
};


function Google:init( opts )
    opts = opts or {};
    opts.discoveryURI = DISCOVERY_URI;
    
    return base['authnz.openidc.OpenIdc'].init( self, opts );
end


-- google does not support nonce value
function Google:genNonce()
    return nil;
end


function Google:finalizeAuthQuery( qry, opts )
    -- set access_type
    if opts.access_type ~= nil and not ACCESS_TYPE[opts.access_type] then
        return false, ('opts.access_type must be %s'):format(
            concat( keys( ACCESS_TYPE ), ' | ' )
        );
    end
    qry.access_type = opts.access_type;
    -- set prompt
    if opts.prompt ~= nil and not PROMPT[opts.prompt] then
        return false, ('opts.prompt msut be %s'):format(
            concat( keys( PROMPT ), ' | ' )
        );
    end
    qry.prompt = opts.prompt;
    
    return true;
end


-- verify id_token
function Google:verifyIdToken( id_token )
    local own = protected(self);
    local res, err = own.client:get( TOKENCHECK_URI, {
        query = {
            id_token = id_token
        }
    });
    
    if err then
        return nil, err;
    elseif res.status ~= 200 then
        err = {};
        for _, v in pairs( res.body ) do
            err[#err+1] = v;
        end
        return nil, table.concat( err, '\n' );
    end
    
    return res.body;
end


return Google.exports;
