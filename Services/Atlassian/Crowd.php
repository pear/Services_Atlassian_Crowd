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
 * Copyright (C) 2008 Infinite Campus Inc., 2008 Luca Corbo
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
 * @copyright 2008 Infinite Campus Inc., 2008 Luca Corbo
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 * @link      http://www.atlassian.com/software/crowd
 * @link      http://confluence.atlassian.com/display/CROWD/SOAP+API
 * @link      http://confluence.atlassian.com/display/CROWDEXT/Integrate+Crowd+with+PHP
 */

/**
 * Exception used to incidate a problem with the Crowd server.
 */
require_once 'Services/Atlassian/Crowd/Exception.php';

/**
 * Class to use Crowd API from PHP
 * 
 * @category  Services
 * @package   Services_Atlassian_Crowd
 * @author    Infinite Campus, Inc.
 * @author    Luca Corbo <lucor@php.net>
 * @copyright 2008 Infinite Campus Inc., 2008 Luca Corbo
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 * @link      http://www.atlassian.com/software/crowd
 * @link      http://confluence.atlassian.com/display/CROWD/SOAP+API
 * @link      http://confluence.atlassian.com/display/CROWDEXT/Integrate+Crowd+with+PHP
 */
class Services_Atlassian_Crowd
{

    /**
     * The Crowd SOAP client
     *
     * @var object
     */
    protected $crowd_client;

    /**
     * Array contains the configuration parameters
     *
     * @var array
     */
    protected $crowd_config;
    
    /**
     * The Crowd application token
     *
     * @var string
     */
    protected $crowd_app_token;

    /**
     * The options required in configuration
     * 
     * @see __construct
     * @var array
     */
    private $_crowd_required_options = array('app_name', 'app_credential', 'service_url');
    
    /**
     * Create an application client using the passed in configuration parameters.
     * 
     * Available options are:
     * 
     * - string  app_name:  The username which the application will use when it 
     *                      authenticates against the Crowd framework as a client.
     *
     * - string  app_credential: The password which the application will use when it 
     *                           authenticates against the Crowd framework 
     *                           as a client.
     * 
     * - string  service_url: The SOAP WSDL URL for Crowd
     *
     * @param array $options optional. An array of options used to connect to Crowd.
     * 
     * @throws Services_Atlassian_Crowd_Exception if there is an error communicating
     *                                            with the Crowd security server.
     */
    public function __construct($options)
    {
        //Check for required parameters 
        foreach ($this->_crowd_required_options as $option) {
            if (!array_key_exists($option, $options)) {
                $exception_message = $option . ' is required!';
                throw new Services_Atlassian_Crowd_Exception($exception_message); 
            }    
        }

        $this->crowd_config = $options;

        // Create the Crowd SOAP client
        try {
            $this->crowd_client = @new SoapClient($this->crowd_config['service_url'], array('exceptions' => true));
        } catch (SoapFault $fault) {
            $exception_message = 'Unable to connect to Crowd. Verify the service_url ' . 
                                 'property is defined and Crowd is running.';
            throw new Services_Atlassian_Crowd_Exception($exception_message . "\n" .
                                                         $fault->getMessage(), 
                                                         $fault);
        }
    }

    /**
     * Authenticates an application client to the Crowd security server.
     * 
     * @return string the application token
     * @throws Services_Atlassian_Crowd_Exception if there is an error communicating
     *                                            with the Crowd security server.
     */
    public function authenticateApplication()
    {
        $credential = array('credential' => $this->crowd_config['app_credential']);
        $name       = $this->crowd_config['app_name'];
        $param      = array('in0' => array('credential' => $credential,
                                           'name'       => $name));
        
        $exception_message = 'Unable to login to Crowd. Verify the app_name and' . 
                             'app_credential properties are defined and valid.';
        try {
            $resp = $this->crowd_client->authenticateApplication($param);
            
            $this->crowd_app_token = $resp->out->token;
    
            if (empty($this->crowd_app_token)) {
                throw new Services_Atlassian_Crowd_Exception($exception_message . "\n" .
                                                             $fault->getMessage());
            }
        } catch (SoapFault $fault) {
            throw new Services_Atlassian_Crowd_Exception($exception_message . "\n" .
                                                         $fault->getMessage(), $fault);
        }

        return $this->crowd_app_token;
    }

    /**
     * Authenticates a principal to the Crowd security server 
     * for the application client.
     * 
     * @param string $name           The username to authenticate
     * @param string $credential     The password of the user to authenticate
     * @param string $user_agent     The user agent
     * @param string $remote_address The remote address
     * 
     * @return string the principal token
     * @throws Services_Atlassian_Crowd_Exception if there is an error communicating
     *                                            with the Crowd security server.
     */
    public function authenticatePrincipal($name, $credential, $user_agent, $remote_address)
    {

        // Build the parameter used to authenticate the principal
        $param = array('in0' => array('name'  => $this->crowd_config['app_name'],
                                      'token' => $this->crowd_app_token),
                       'in1' => array('application' => $this->crowd_config['app_name'],
                                      'credential'  => array('credential' => $credential),
                                      'name'        => $name,
                                      'validationFactors' => array(array('name'  => 'User-Agent',
                                                                         'value' => $user_agent),
                                                                   array('name'  => 'remote_address', 
                                                                         'value' => $remote_address))));

        // Attempt to authenticate the user (principal) via Crowd.
        try {
            $resp = $this->crowd_client->authenticatePrincipal($param);
        } catch (SoapFault $fault) {
            throw new Services_Atlassian_Crowd_Exception($fault->getMessage(), $fault);
            
        }

        // Get the principal's token
        return $resp->out;
    }

    /**
     *  Calls a remote method
     * 
     * @param string $method The remote method to call
     * @param mixed  $args   The parameters to use with remote method
     * 
     * @return object | true
     * @throws Services_Atlassian_Crowd_Exception if there is an error communicating
     *                                            with the Crowd security server.
     * 
     * @method    object isValidPrincipalToken(array($princ_token, $user_agent, $remote_address)) 
     *                    Determines if the principal's current token is still valid in Crowd.
     * @method    boolean invalidatePrincipalToken(string $princ_token) 
     *                    Invalidates a token for for this principal for all application clients in Crowd.
     * @method    object findPrincipalByToken(string $princ_token) 
     *                   Finds a principal by token.
     * @method    object findGroupMemberships(string $princ_name) 
     *                   Finds all of the groups the specified principal is in.
     * 
     */
    
    public function __call($method, $args)
    {
        if (!is_array($args)) {
            $args[0] = $args;
        }
        
        //Supported methods of Crowd's API
        switch ($method) {
        case 'findGroupMemberships':
        case 'findPrincipalByToken':
        case 'invalidatePrincipalToken':
            $params = array('in0' => array('name'  => $this->crowd_config['app_name'],
                                           'token' => $this->crowd_app_token),
                            'in1' => $args[0]);
            break;
        case 'isValidPrincipalToken':
            $params = array('in0' => array('name'  => $this->crowd_config['app_name'],
                                           'token' => $this->crowd_app_token),
                            'in1' => $args[0],
                            'in2' => array(array('name'  => 'User-Agent',
                                                 'value' => $args[1]),
                                           array('name'  => 'remote_address', 
                                                 'value' => $args[2])));
            break;
        default:
            throw new Services_Atlassian_Crowd_Exception(
                'Method (' . $method . ') is not implemented'
            );
            break;
        }
                
        try {
            $resp = $this->crowd_client->$method($params);
            if (isset($resp->out)) {
                return $resp->out;
            } else {
                return true;
            }
        } catch (SoapFault $fault) {
            throw new Services_Atlassian_Crowd_Exception($fault->getMessage(),
                                                         $fault);
        }
    }
}
?>
