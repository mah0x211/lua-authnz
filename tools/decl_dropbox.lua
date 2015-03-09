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
  
  tool/decl_dropbox.lua
  lua-authnz
  
  Created by Masatoshi Teruya on 15/03/05.
  
--]]

local CONTENT_URI   = 'https://api-content.dropbox.com/1';
local NOTIFY_URI    = 'https://api-notify.dropbox.com/1';

return {
    BASE_URI = 'https://api.dropbox.com/1',
    REQUEST_HEADER = {
        -- NOTE: should set Accept header
        ['Accept'] = 'application/json'
    },
    API = {
        -- Core API
        -- account
        accountInfo = {
            get = '/account/info'
        },
        -- files and metadata
        files = {
            uri = CONTENT_URI,
            get = '/files/auto/%s',
            fmt = 1
        },
        filesPut = {
            uri = CONTENT_URI,
            put = '/files_put/auto/%s',
            fmt = 1
        },
        metadata = {
            get = '/metadata/auth/%s',
            fmt = 1
        },
        delta = {
            post = '/delta'
        },
        deltaLatestCursor = {
            post = '/delta/latest_cursor'
        },
        longPollDelta = {
            uri = NOTIFY_URI,
            get = '/longpoll_delta'
        },
        revisions = {
            get = '/revisions/auto/%s',
            fmt = 1
        },
        restore = {
            post = '/restore/auto/%s',
            fmt = 1
        },
        search = {
            get = '/search/auto/%s',
            fmt = 1
        },
        shares = {
            post = '/shares/auto/%s',
            fmt = 1
        },
        media = {
            post = '/media/auto/%s',
            fmt = 1
        },
        copyRef = {
            get = '/copyRef/auto/%s',
            fmt = 1
        },
        thumbnails = {
            uri = CONTENT_URI,
            get = '/thumbnails/auto/%s',
            fmt = 1
        },
        previews = {
            uri = CONTENT_URI,
            get = '/previews/auto/%s',
            fmt = 1
        },
        chunkedUpload = {
            uri = CONTENT_URI,
            put = '/chunked_upload'
        },
        commitChunkedUpload = {
            uri = CONTENT_URI,
            post = '/commit_chunked_upload/auto/%s',
            fmt = 1
        },
        sharedFolders = {
            get = '/shared_folders/%s',
            fmt = 1
        },
        -- file operations
        fileopsCopy = {
            post = '/fileops/copy'
        },
        fileopsCreateFolder = {
            post = '/fileops/create_folder'
        },
        fileopsDelete = {
            post = '/fileops/delete'
        },
        fileopsMove = {
            post = '/fileops/move'
        },
        -- Datastore API
        listDatastore = {
            get = '/datastores/list_datastores'
        },
        getDatastore = {
            get = '/datastores/get_datastore'
        },
        getOrCreateDatastore = {
            post = '/datastores/get_or_create_datastore'
        },
        createDatastore = {
            post = '/datastores/create_datastore'
        },
        deleteDatastore = {
            post = '/datastores/delete_datastore'
        },
        getDeltas = {
            get = '/datastores/get_deltas'
        },
        putDelta = {
            post = '/datastores/put_delta'
        },
        getSnapshot = {
            get = '/datastores/get_snapshot'
        },
        await = {
            get = '/datastores/await'
        }
    }
};

