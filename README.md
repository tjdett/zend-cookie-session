# CookieJar Save Handler #

This class provides a save handler for a pure cookie-based session in Zend Framework. This was first introduced in Ruby on Rails by Ryan Dingle, and has been adapted here for Zend. This was last tested on Zend Framework v 1.10.

See http://ryandaigle.com/articles/2007/2/21/what-s-new-in-edge-rails-cookie-based-sessions for the original blog post by Ryan on how this works for rails, and how it's secured.

## Installation ##

This file should be placed under the library folder of your Zend instance. Feel free to rename the default namespace to your own, just make sure you add it in a directory structure following the Zend Coding Standards (http://framework.zend.com/manual/en/coding-standard.html). 

## Configuration ##

The constructor accepts an array of key=>value based options. These options are:

* 'cookie_prefix': This is a prefix for the cookie names. For example, if you set the prefix to 'session_store_', all cookies will be named with numerical suffixes, like 'session_store_1', 'session_store2', etc. The default is 'session_store_'

* 'encryption_salt': This is a salt passed when the save handler encrypts the cookie data. Set this to anything you wish. Be secure!

* 'cookie_limit': This is a limit to the number of cookies the save handler is allowed to create. Each cookie is allowed a 4k data limit, after which a new cookie is created. Be aware that all servers have limits to how large a request header can be. It's strongly recommended you allow no more than 1 cookie. Don't abuse the session. The default is 1.

* 'cookie_expiry': How long (in minutes) before the cookie is set to expire. This is obviously renewed with every request. The default is 30 minutes.

## Feedback / Contribution ##

Feedback and improvements are always welcome. Email bcelenza@gmail.com for feedback, or fork the git repository to contribute.

## License ##

See LICENSE for details.