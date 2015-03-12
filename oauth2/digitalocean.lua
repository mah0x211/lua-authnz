--[[
  
  Copyright (C) 2015 Masatoshi Teruya

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
  
  oauth2/digitalocean.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 15/03/09.
  
--]]

-- module
local typeof = require('util.typeof');
local DigitalOceanCli = require('digitalocean');
-- constants
local AUTHORIZE_URI = 'https://cloud.digitalocean.com/v1/oauth/authorize';
local TOKEN_URI     = 'https://cloud.digitalocean.com/v1/oauth/token';
-- class
local DigitalOcean = require('halo').class.DigitalOcean;


DigitalOcean.inherits {
    'authnz.oauth2.OAuth2'
};


function DigitalOcean:init( opts )
    opts = opts or {};
    if not typeof.table( opts ) then
        return nil, 'opts must be table';
    end
    -- add required fields
    opts.authorizeURI = AUTHORIZE_URI;
    opts.tokenURI = TOKEN_URI;
    
    return base['authnz.oauth2.OAuth2'].init( self, opts );
end


function DigitalOcean:createClient( token )
    return DigitalOceanCli.new( protected(self).req, token );
end


return DigitalOcean.exports;
