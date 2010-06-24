<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */


/**
 * Services_Atlassian_Crowd_ApplicationSoapCredentials is a helper class to
 * provide connection information to a Crowd soap-based security server. 
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

class Services_Atlassian_Crowd_ApplicationSoapCredentials
{
    // The URL of the Crowd security server's WSDL.
    public $wsdl;
    // The name of the application used to authenticate to Crowd
    public $application_name;
    // The password for the given $application_name
    public $application_credential;
    // An authentication token assigned to the application
    public $application_token = NULL;

    /**
     * Constructor.
     * Validates the parameters and assigns them to the class variables.
     *
     * @param String $wsdl
     *   The URL of the Crowd security server's WSDL
     * @param String $application_name
     *   The name of the application used to authenticate to Crowd
     * @param String $application_credential
     *   The password for the given $application_name
     * @param optional String $application_token
     *   An authentication token assigned to the application (if this is known,
     *   providing this will save 1 remote call, increasing performance)
     */
    public function __construct($wsdl, $application_name, $application_credential, $application_token = NULL)
    {
        // validate the arguments
        if(!(is_string($wsdl) && is_string($application_name) && is_string($application_credential) && (is_string($application_token) || is_null($application_token)))) {
            $msg = 'Invalid argument: Services_Atlassian_Crowd_ApplicationSoapCredentials constructor requires 3 string arguments, with an optional fourth string argument.';
            throw new InvalidArgumentException($msg);
        }
        $this->wsdl = $wsdl;
        $this->application_name = $application_name;
        $this->application_credential = $application_credential;
        if(is_string($application_token)) {
            $this->application_token = $application_token;
        }
    }
}
?>
