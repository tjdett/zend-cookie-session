<?php
/**
 * This class provides a save handler for a pure cookie-based session. This was 
 * first introduced in Ruby on Rails by Ryan Dingle, and has been adapted here
 * for Zend.
 * 
 * LICENSE
 * 
 * The MIT License
 * 
 * Copyright (c) 2011 Brian J. Celenza <bcelenza@gmail.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 * 
 * @author Brian J. Celenza <bcelenza@gmail.com>
 * @category BJC
 * @package BJC_Session
 * @copyright Copyright (c) 2011 Brian J. Celenza <bcelenza@gmail.com>
 * @license http://creativecommons.org/licenses/MIT/ The MIT License
 *
 */
class BJC_Session_SaveHandler_CookieJar implements Zend_Session_SaveHandler_Interface
{
	
	const EXPIRY_TIME_DELIMITER = '###';
	
	/**
     * Default options for this cookie jar
     * 
     * @var array
     */
    private $_options = array(
        // prefix for all cookie names, will be suffixed with a number
        'cookie_prefix'   => 'session_store_',
        // salt to use when encrypting the session data
        'encryption_salt' => '99111a6f10d3951b11eb68ecaf9b56fb',
        // the number of cookies we're allowed to create for the session store
        'cookie_limit'    => 1,
        // cookie expiration in minutes
        'cookie_expiry'   => 30
    );
	
	/**
	 * Container for un-encrypted, unserialized session data
	 * 
	 * @var string
	 */
	private $_cookieData = '';
	
	/**
	 * Constructor accepts an array of options to override the defaults
	 * 
	 * @param array $options
	 */
	public function __construct(array $options = array())
	{
		foreach($options as $key => $value) {
			$this->_options[$key] = $value;
		}
	}
	
    /**
     * Open Session - retrieve resources
     *
     * @param string $save_path
     * @param string $name
     */
    public function open($save_path, $name)
    {
    	$assembled_session_string = '';
    	
    	// get the cookies array from the request object
    	$cookies = $this->_getRequest()->getCookie();
    	// search the cookies array for "our" cookies
    	for($i = 0; $i < $this->_options['cookie_limit']; $i++) {
    		$cookieName = $this->_options['cookie_prefix'] . $i;
    		
    		// if the cookie doesnt exist, we're done searching
    		if(!array_key_exists($cookieName, $cookies)) {
    			break;
    		}
    		
    		// append this cookie's value on the assembled string
    		$assembled_session_string .= $cookies[$cookieName];
    	}
    	
    	if(!empty($assembled_session_string)) {
    		// decrypt the string
	        $this->_cookieData = rtrim(
	            mcrypt_decrypt(
	                MCRYPT_RIJNDAEL_256, 
	                md5($this->_options['encryption_salt']), 
	                base64_decode($assembled_session_string), 
	                MCRYPT_MODE_CBC, 
	                md5(md5($this->_options['encryption_salt']))
	            ), 
	            "\0"
	        );
    	}
    	
    	// If we have an expiry time header, strip it off
    	if (strpos($this->_cookieData, self::EXPIRY_TIME_DELIMITER) === 0) {
    		$this->_cookieData = $this->_removeExpiryTimePrefix(
    			$this->_cookieData,
    			$this->_options['enforce_expiry']
    		);
    	}
    	
    	return true;
    }

    /**
     * Close Session - free resources
     *
     */
    public function close()
    {
    	// nothing to do here
    	return true;
    }

    /**
     * Read session data
     *
     * @param string $id
     */
    public function read($id)
    {
    	return $this->_cookieData;
    }

    /**
     * Write Session - commit data to resource
     *
     * @param string $id
     * @param mixed $data
     */
    public function write($id, $data)
    {
    	// if necessary, append expiry time prefix inside encrypted data
    	if ($this->_options['enforce_expiry']) {
    		$data = $this->_addExpiryTimePrefix(
    			$data, 
    			$this->_options['cookie_expiry']
    		);
    	}
    	
        // encrypt and encode data
        $data = base64_encode(
            mcrypt_encrypt(
                MCRYPT_RIJNDAEL_256, 
                md5($this->_options['encryption_salt']), 
                $data, 
                MCRYPT_MODE_CBC, 
                md5(md5($this->_options['encryption_salt']))
            )
        );
        $data = urlencode($data);
        
        // split data
        $data_chunks = str_split($data, 4000);
        $chunk_count = sizeof($data_chunks);
        
        // check to make sure we have not violated our max cookie count
        if($chunk_count > $this->_options['cookie_limit']) {
        	throw new Zend_Session_Exception(
        	   'Cookie limit of ' . $this->_options['cookie_limit'] . ' exceeded in cookie session store.'
            );
        }
        
        // verify that we can send headers
        if(!$this->_getResponse()->canSendHeaders()) {
            throw new Exception('Unable to write cookies to response.');
        }
        
        // save split data in cookies
        for($i = 0; $i < $chunk_count; $i++) {
        	// create the new cookie
        	$cookieString = sprintf(
        	    '%s=%s; expires=%s; path=/; domain=%s; httponly', 
        	    $this->_options['cookie_prefix'] . $i, 
        	    $data_chunks[$i],
        	    $this->_getExpirationDate($this->_options['cookie_expiry']),
        	    array_key_exists('HTTP_HOST',$_SERVER) ? $_SERVER['HTTP_HOST'] : $_SERVER['SERVER_NAME']
        	);
        	// add secure flag if HTTPS
            if($_SERVER['HTTPS'] == "on") $cookieString .= "; secure";
        	$this->_getResponse()->setHeader('Set-Cookie', $cookieString);
        }
        
        return true;
    }

    /**
     * Destroy Session - remove data from resource for a given session id
     *
     * @param string $id
     */
    public function destroy($id)
    {
        // verify that we can send headers
        if(!$this->_getResponse()->canSendHeaders()) {
            throw new Exception('Unable to write cookies to response.');
        }
        
    	// set all cookies values to nothing
    	$cookies = $this->_getRequest()->getCookie();
	    for($i = 0; $i < $this->_options['cookie_limit']; $i++) {
    		$cookieName = $this->_options['cookie_prefix'] . $i;

            // if the cookie doesnt exist, we're done searching
            if(!array_key_exists($cookieName, $cookies)) {
                break;
            }

            // create the new cookie
            $cookieString = sprintf(
                '%s=%s; expires=%s; path=/; domain=%s;', 
                $this->_options['cookie_prefix'] . $i, 
                '',
                $this->_getExpirationDate(),
                $_SERVER['SERVER_NAME']
            );
            $this->_getResponse()->setHeader('Set-Cookie', $cookieString);
    	}
    	
    	return true;
    }

    /**
     * Garbage Collection - remove old session data older
     * than $maxlifetime (in seconds)
     *
     * @param int $maxlifetime
     */
    public function gc($maxlifetime)
    {
    	// nothing to do here
    	return true;
    }
    
    /**
     * Returns the current request object 
     * 
     * @return Zend_Controller_Request_Abstract
     */
    private function _getRequest()
    {
    	return Zend_Controller_Front::getInstance()->getRequest();
    }
    
    /**
     * Returns the current response object
     * 
     * @return Zend_Controller_Response_Abstract
     */
    private function _getResponse()
    {
    	return Zend_Controller_Front::getInstance()->getResponse();
    }
    
    /**
     * Returns an RFC850 formatted expiration date based on number of minutes in the future
     * 
     * @param int $minutes
     * @return string
     */
    private function _getExpirationDate($minutes = 0)
    {
    	$expiration_time = time() + ($minutes * 60);
        $date_time = new DateTime(null, new DateTimeZone('GMT'));
        $date_time->setTimestamp($expiration_time);
        return $date_time->format(DateTime::COOKIE);
    }
    
    /**
     * Add an expiry time prefix to the session data.
     * 
     * @param string $data
     * @param int $minutes
     * @return string
     */
    private function _addExpiryTimePrefix($data, $minutes) {
        $expiration_time = time() + ($minutes * 60);
        $data = implode(
            self::EXPIRY_TIME_DELIMITER, 
            array('',$expiration_time,$data)
        );
        return $data;
    }
    
    /**
     * Removes the expiry time prefix on session data. If $enforce is set to 
     * true, then an empty string will returned if the expiry time is in the 
     * past.
     * 
     * @param string $data
     * @param boolean $enforce
     * @return string
     */
    private function _removeExpiryTimePrefix($data, $enforce = FALSE) {
        list($empty, $timestamp, $data) = explode(
            self::EXPIRY_TIME_DELIMITER, 
            $this->_cookieData, 
            3
        );
        if ($enforce)
            return (time() <= $timestamp) ? $data : '';
        return $data;
    }
}
