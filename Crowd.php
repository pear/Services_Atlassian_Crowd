<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Services_Atlassian_Crowd is a package to use Atlassian Crowd from PHP
 *
 * Crowd is a web-based single sign-on (SSO) tool 
 * that simplifies application provisioning and identity management.
 * 
 * This package is derived from the PHP Client Library for Atlassian Crowd
 * class written by Infinite Campus, Inc.
 * 
 * PHP version 5
 * 
 * Copyright (C) 2010 Marcus Deglos
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @category  Services
 * @package   Services_Atlassian_Crowd
 * @author    Infinite Campus, Inc.
 * @author    Luca Corbo <lucor@php.net>
 * @author    Marcus Deglos <marcus@deglos.com>
 * @copyright 2010 Marcus Deglos
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 * @link      http://www.atlassian.com/software/crowd
 * @link      http://confluence.atlassian.com/display/CROWD/SOAP+API
 * @link      http://confluence.atlassian.com/display/CROWDEXT/Integrate+Crowd+with+PHP
 */

// Load includes
require_once('Services/Atlassian/Crowd/Exception.php');
require_once('Services/Atlassian/Crowd/ApplicationSoapCredentials.php');
require_once('Services/Atlassian/Crowd/SecurityServer/Interface.php');
require_once('Services/Atlassian/Crowd/SecurityServer/SOAP.php');

class Services_Atlassian_Crowd
{

    // $securityServer will be an implementation of Services_Atlassian_Crowd_SecurityServer_Interface 
    private $securityServer;


    /**
     * Constructor.
     * If credentionals are provided, this will try to invoke the default Soap
     * implementation.  This is the recommended way of using this class.
     *
     * @param optional Object applicationSettings
     *   If provided, try to connect using the default Soap handler.
     *
     * @throws Services_Atlassian_Crowd_ServerUnreachableException
     *   if the remote Crowd server cannot be reached.
     */
    function __construct($soapCredentials = NULL)
    {
        if (is_a($soapCredentials, 'Services_Atlassian_Crowd_ApplicationSoapCredentials')) {
            // try to create a Soap connection.
            $server = new Services_Atlassian_Crowd_SecurityServer_SOAP($soapCredentials->wsdl);
            $this->securityServer = $server;
            $this->securityServer->setSoapCredentials($soapCredentials);
        }
        elseif(!is_null($soapCredentials)) {
            /**
             * if a paramater was passed, but ISN'T a valid 
             * Services_Atlassian_CrowdApplicationSoapSettings object, 
             * throw an Exception.
             */
            $msg = 'Invalid argument: Services_Atlassian_Crowd constructor expects NULL or a Services_Atlassian_Crowd_ApplicationSoapCredentials object.';
            throw new InvalidArgumentException($msg);
        }
    }

    /**
     * Set the security server to use.
     * This may be useful if you wish to use a mock object instead of the 
     * default Soap implementation.
     */
    function setSecurityServer($server)
    {
        if (!is_a($server, 'Services_Atlassian_Crowd_SecurityServer_Interface')) {
            $msg = 'Invalid argument: setSecurityServer() expects a Services_Atlassian_Crowd_SecurityServer_Interface object.';
            throw new InvalidArgumentException($msg);
        }
        $this->securityServer = $server;
    }

    /**
     * getAuthenticationToken
     * Provide the authentication token.
     *
     * @return String|Null
     *   The token (if authenticated), or Null.
     */
    public function getAuthenticationToken()
    {
        return $this->securityServer->getAuthenticationToken();
    }

    /**
     * Magic __call method: pass all Crowd calls to the security server.
     */
    function __call($method, $arguments)
    {
        // Validate that the securityServer is correctly configured
        if(!is_a($this->securityServer, 'Services_Atlassian_Crowd_SecurityServer_Interface')) {
            $msg = 'Services_Atlassian_Crowd is not configured correctly.';
            throw new RuntimeException($msg);
        }
        // validate the method and arguments
        elseif(!(is_string($method) && is_array($arguments))) {
            $msg = 'Magic method __call has been called with invalid parameters - __call expects a string as argument 1 and an array as argument 2.';
            throw new InvalidArgumentException($msg);           
        }
        // Validate that the method can be called.
        elseif(!in_array($method, get_class_methods($this->securityServer))) {
            $msg = 'Method ' . $method . ' is not supported by Crowd security server object ' . get_class($this->securityServer);
            throw new BadMethodCallException($msg);         
        }
        return call_user_func_array(array($this->securityServer, $method), $arguments);
    }
}
?>
