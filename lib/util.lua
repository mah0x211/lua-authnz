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
   
  authnz.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 14/12/10.
  
--]]

-- module
local flatten = require('util.table').flatten;
local typeof = require('util.typeof');
local encodeURI = require('url').encodeURI;
local gettimeofday = require('process').gettimeofday;
local siphash48 = require('siphash').encode48;
local random = math.random;
-- init random seed
math.randomseed( gettimeofday() );


local function encodeQuery( tbl )
    local etbl = {};
    local idx = 0;
    
    for k, v in pairs( flatten( tbl ) ) do
        idx = idx + 1;
        etbl[idx] = encodeURI( k ) .. '=' .. encodeURI( tostring( v ) );
    end
    
    return idx > 0 and table.concat( etbl, '&' ) or nil;
end


-- generate random value
local function genRandom()
    return siphash48( gettimeofday(), tostring( random() ):sub( 1, 16 ) );
end


local function createClient( own, OPTIONS, opts )
    local opt, ok, err, client;
    
    -- request client params
    OPTIONS.client = {
        req = true,
        typ = 'string',
        def = 'luasocket',
        enm = {
            luasocket = 'luasocket',
            resty = 'resty',
        },
        msg = 'opts.client must be "luasocket" or "resty"'
    };
    OPTIONS.client_gateway = {
        typ = 'string',
        msg = 'opts.client_gateway must be string'
    };
    OPTIONS.timeout = {
        typ = 'uint',
        msg = 'opts.timeout must be uint'
    };

    -- check params
    for k, v in pairs( OPTIONS ) do
        opt = opts[k];
        if not opt then
            -- set default value
            opt = v.def;
            -- requere but no default value
            if v.req and not opt then
                return nil, v.msg;
            elseif k == 'client' then
                client = opt;
                ok, opt, err = pcall( require, 'httpcli.' .. opt );
                if not ok then
                    return nil, 'opts.client: ' .. err;
                end
            end
        -- type check
        elseif not typeof[v.typ]( opt ) then
            return nil, v.msg;
        -- enum check
        elseif v.enm then
            opt = v.enm[opt];
            if not opt then
                return nil, v.msg;
            elseif k == 'client' then
                client = opt;
                ok, opt, err = pcall( require, 'httpcli.' .. opt );
                if not ok then
                    return nil, 'opts.client: ' .. err;
                end
            end
        end
        own[k] = opt;
    end
    
    -- create http client
    if client == 'luasocket' then
        return own.client.new( true, own.timeout );
    -- httpcli.resty
    elseif not own.client_gateway then
        return nil, OPTIONS.client_gateway.msg;
    else
        return own.client.new( own.client_gateway, true, own.timeout );
    end
end


return {
    encodeQuery     = encodeQuery,
    genRandom       = genRandom,
    createClient    = createClient
};
