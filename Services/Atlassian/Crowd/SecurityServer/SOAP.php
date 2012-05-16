<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Services_Atlassian_Crowd_SecurityServer_SOAP is a soap-based implementation
 * of a Crowd security server.
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

class Services_Atlassian_Crowd_SecurityServer_SOAP implements Services_Atlassian_Crowd_SecurityServer_Interface
{
    // A php SoapClient object
    private $soapClient;
    // Credentials used to authenticate to Crowd.
    private $applicationCredentials;


    /**
     * Constructor
     * If called with a WSDL, attempt to connect via a php SoapClient object
     * @see SoapClient::SoapClient
     *
     * @throws InvalidArgumentException 
     *   if the supplied arguments are not valid.
     * @throws Services_Atlassian_Crowd_ServerUnreachableException
     *   if the remote Crowd server cannot be reached.
     */
    public function __construct($wsdl = NULL, $options = array())
    {
        // validate the arguments
        if (!((is_string($wsdl) || is_null($wsdl)) && is_array($options))) {
            $msg = 'Invalid argument: Atlassian_Services_Crowd_SecurityServer_SOAP constructor expects NULL or a String for the $wsdl argument, and an array for the $options argument.';
            throw new InvalidArgumentException($msg);           
        }

        if (is_string($wsdl)) {
            try {

               /*
                * If PHP goes fatal here instead of throwing an exception, check if
                * you have Xdebug installed.  If so, you are likely experiencing
                * http://bugs.xdebug.org/view.php?id=705  Fun! :/
                */
	
                $options['exceptions'] = true;
                $soapClient = new SoapClient($wsdl, $options);

                $this->soapClient = $soapClient;
            }
            catch(SoapFault $e) {
                if (property_exists($e, 'faultcode')) {
                    if ($e->faultcode == 'WSDL') {
                        // SoapClient can't connect to server.
                        $msg = 'Could not connect to remote Crowd server.';
                        throw new Services_Atlassian_Crowd_ServerUnreachableException($msg);
                    }
                }
            }
        }
    }

    /**
     * getAuthenticationToken
     * Provide the authentication token assigned to the application.
     *
     * @return String|Null
     *   The token (if authenticated), or Null.
     */
    public function getAuthenticationToken()
    {
        return $this->applicationCredentials->application_token;
    }

    
    /**
     * Provide a soapClient to handle all remote calls.
     * 
     * @param SoapClient $client
     *   The SoapClient to use in order to connect to the Crowd server.
     */
    public function setSoapClient(SoapClient $client)
    {
        $this->soapClient = $client;
    }
    
    
    /**
     * Configure the credentials
     * 
     * @param Services_Atlassian_CrowdApplicationSoapCredentials $soapCredentials
     *   The credentials to supply when connecting to the Crowd server.
     */
    public function setSoapCredentials(Services_Atlassian_Crowd_ApplicationSoapCredentials $soapCredentials)
    {
        $this->applicationCredentials = $soapCredentials;
    }


    ##########################################################
    # Expose Crowd API interfaces:
    # - abstract SOAP
    # - Catch SOAP faults, throw Atlassian_Crowd exceptions
    ##########################################################
    
    /**
     * addAttributeToGroup()
     * Example: $crowd->addAttributeToGroup('foo', 'bar', 'baz');
     * Example: $crowd->addAttributeToGroup('foo', 'bar', array('baz', 'bzy');
     *
     * @param String $group
     *   The name of the group
     * @param String $attribute_name
     *   The name of the attribute to add
     * @param Array|String $attribute_value
     *   The value(s) to assign to the attribute
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException 
     *   if the supplied arguments are not valid.
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group was not found
     */
    public function addAttributeToGroup($group, $attribute_name, $attribute_value)
    {
        // validate the input
        // validate the input
        if (!(is_string($group) && is_string($attribute_name) && (is_string($attribute_value) || is_array($attribute_value)))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $group,
            array(
                'name' => $attribute_name,
                'value' => $attribute_value,
            )
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);

        try
        {
            $result = $this->soapClient->addAttributeToGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * addAttributeToPrincipal()
     * Example: $crowd->addAttributeToPrincipal('foo', 'bar', 'baz');
     * Example: $crowd->addAttributeToPrincipal('foo', 'bar', array('baz', 'bzy');
     *
     * @param String $principal
     *   The name of the principal
     * @param String $attribute_name
     *   The name of the attribute to add
     * @param Array|String $attribute_value
     *   The value(s) to assign to the attribute
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the principal
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal was not found
     */
    public function addAttributeToPrincipal($principal, $attribute_name, $attribute_value)
    {
        // validate the input
        if (!(is_string($principal) && is_string($attribute_name) && (is_string($attribute_value) || is_array($attribute_value)))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
            $principal,
            array(
                'name' => $attribute_name,
                'values' => is_array($attribute_value) ? $attribute_value : array($attribute_value),
            )
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->addAttributeToPrincipal($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * addGroup()
     * Example: $crowd->addGroup('foo');
     * Example: $crowd->addGroup('foo', 'Lorem ipsum');
     * Example: $crowd->addGroup('foo', 'Lorem ipsum', TRUE);
     * Example: $crowd->addGroup('foo', '', TRUE);
     *
     * @param String $name
     *   The name of the group
     * @param optional String $description
     *   The description for the group
     * @param optional Boolean $active
     *   Set to TRUE if the group should be initially enabled
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to add the group
     * @throws Services_Atlassian_Crowd_InvalidArgumentException
     *   if the group could not be added (for example, the group name is not
     *   permitted by Crowd's internal rules)
     */
    public function addGroup($name, $description = '', $active = FALSE)
    {
        // validate the input
        if (!(is_string($name) && is_string($description) && is_boolean($active))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $group = array('name' => $name);
        if ($active) {
            $group['active'] = $active;
        }
        if ($description) {
            $group['description'] = $description;
        }
        $params = array(
            $this->_getToken(), 
            $group,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->addGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * addPrincipal()
     * Example: $crowd->addPrincipal('foo', 'bar', array('mail' => 'foo@example.com', 'givenName' => 'baz', 'sn' => 'buz'));
     * Example: $crowd->addPrincipal('foo', 'bar', array('mail' => 'foo@example.com', 'givenName' => 'baz', 'sn' => 'buz'), true);
     *
     * @param String $name
     *   The name of the principal
     * @param String $credential
     *   The password to assign to the principal
     * @param Array $attributes
     *   A key-value array map of attributes.
     *   Required keys are:
     *   - mail       email address
     *   - givenName  first name
     *   - sn         surname
     * @param Boolean $active
     *   Set to true to enable the principal's account.  Defaults to disabled.
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to add the principal
     * @throws Services_Atlassian_Crowd_Exception
     *   if the principal cannot be added (for example, a principal with the
     *   same name already exists)
     */
    public function addPrincipal($name, $credential, $attributes, $active = false)
    {
        // validate the input
        if (!(is_string($name) && is_string($credential) && is_array($attributes) && is_bool($active))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        elseif(!(array_key_exists('mail', $attributes) && array_key_exists('givenName', $attributes) && array_key_exists('sn', $attributes))) {
            $msg = 'Invalid arguments: attributes must include the keys "mail", "givenName" and "sn" for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        elseif(!(is_string($attributes['mail']) && is_string($attributes['givenName']) && is_string($attributes['sn']))) {
            $msg = 'Invalid arguments: attributes "mail", "givenName" and "sn" must each be a String value in ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        $principal = array(
            'name' => $name,
            'active' => $active,
            'attributes' => array(),
        );
        foreach($attributes as $key => $value) {
            $principal['attributes'][] = is_array($value) 
                ? array('name' => $key, 'values' => $value)
                : array('name' => $key, 'values' => array($value));
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
            $principal,
            array('credential' => $credential),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);

        try
        {
            $this->soapClient->addPrincipal($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * addPrincipalToGroup()
     * Example: $crowd->addPrincipalToGroup('foo', 'bar');
     *
     * @param String $principal
     *   The name of the principal
     * @param String $group
     *   The name of the group
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to add the principal to the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal or group could not be found
     */
    public function addPrincipalToGroup($principal, $group)
    {
        // validate the input
        if (!(is_string($principal) && is_string($group))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
            $principal,
            $group,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);

        try
        {
            $this->soapClient->addPrincipalToGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * addPrincipalToRole()
     * Example: $crowd->addPrincipalToRole('foo', 'bar');
     *
     * @param String $principal
     *   The name of the principal
     * @param String $role
     *   The name of the role
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to add the principal to the role
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal or role could not be found
     */
    public function addPrincipalToRole($principal, $role)
    {
        // validate the input
        if (!(is_string($principal) && is_string($role))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
            $principal,
            $role,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);

        try
        {
            $this->soapClient->addPrincipalToRole($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * addRole()
     * Example: $crowd->addRole('foo');
     * Example: $crowd->addRole('foo', 'Lorem ipsum');
     * Example: $crowd->addRole('foo', 'Lorem ipsum', TRUE);
     * Example: $crowd->addRole('foo', '', TRUE);
     *
     * @param String $role
     *   The name of the role to add
     * @param optional String $description
     *   The description for the role
     * @param optional Boolean $active
     *   Set to TRUE if the role should be initially enabled
     * @return Boolean
     *   True on success
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to add the role
     * @throws Services_Atlassian_Crowd_InvalidArgumentException
     *   if the role could not be added (for example, the role name is not
     *   permitted by Crowd's internal rules)
     */
    public function addRole($role, $description = '', $active = FALSE)
    {
        // validate the input
        if (!(is_string($role) && is_string($description) && is_bool($active))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            array('name' => $role),
        );
        if ($description) {
            $params[1]['description'] = $description;
        }
        if ($active) {
            $params[1]['active'] = $active;
        }
        $params = call_user_func_array(array('self', '_soapEncode'), $params);

        try
        {
            $this->soapClient->addRole($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * authenticateApplication()
     *   Authenticate your remote application to the Crowd server.
     *   For normal use, authentication will be handled automatically - there
     *   is no need to call this method.  Use this method for tasks such as
     *   validating the credentials of an application.
     *
     * @param String $application_name
     *   The name to use for the application to authenticate to Crowd.
     * @param String $application_password
     *   The password associated with the supplied name.
     * @return String
     *   The authentication token granted by Crowd to the application.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */
    public function authenticateApplication ($application_name, $application_password)
    {
        if (!(is_string($application_name) && is_string($application_password))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);
        }
        
        // encode our data into the remote call signature.
        $params = array(
            array(
                'name' => $application_name,
                'credential' => array('credential' => $application_password)
            )
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->authenticateApplication($params);
            return $result->out->token;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }
    
    
    

    /**
     * authenticatePrincipal()
     *   Authenticate a principal to the Crowd server, open an SSO session and 
     *   return an SSO token to the principal.  Note that SSO sessions are tied
     *   to the supplied user-agent and remote IP address.
     *   If you don't want to open an SSO session for the principal, use 
     *   authenticatePrincipalSimple().
     * Example: $token = $crowd->authenticatePrincipal('foo', 'bar', 'baz', '192.168.0.55');
     * 
     * @param String $name
     *   The principal's user name.
     * @param String $credential
     *   The principal's password.
     * @param String $user agent
     *   The user-agent supplied by the principal to the application
     * @param String $remote_ip_address
     *   The IP address used by principal
     * @return String
     *   The authentication token to give to the principal. 
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to authenticate the principal
     * @throws Services_Atlassian_Crowd_InvalidPrincipalAuthenticationException
     *   if the principal's credentials are invalid
     * @throws Services_Atlassian_Crowd_InactiveAccountException
     *   if the principal's account is inactive
     */
    public function authenticatePrincipal ($name, $credential, $user_agent, $remote_ip_address)
    { 
        // validate input.
        if (!(is_string($name) && is_string($credential) && is_string($user_agent) && is_string($remote_ip_address))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            array(
                'application' => $this->applicationCredentials->application_name,
                'name'        => $name,
                'credential'  => array('credential' => $credential),
                'validationFactors' => array(
                    array('name'  => 'User-Agent',     'value' => $user_agent),
                    array('name'  => 'remote_address', 'value' => $remote_ip_address)
                )
            )
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->authenticatePrincipal($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * authenticatePrincipalSimple()
     *   Authenticate a principal to the Crowd server without starting an SSO 
     *   session.  Use for simple username/password verification.
     * Example: $token = $crowd->authenticatePrincipalSimple('foo', 'bar');
     * 
     * @param String $name
     *   The principal's user name.
     * @param String $credential
     *   The principal's password.
     * @return String
     *   The authentication token to give to the principal. 
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to authenticate the principal
     * @throws Services_Atlassian_Crowd_InvalidPrincipalAuthenticationException
     *   if the principal's credentials are invalid
     * @throws Services_Atlassian_Crowd_InactiveAccountException
     *   if the principal's account is inactive
     */
    public function authenticatePrincipalSimple ($name, $credential)
    { 
        // validate input.
        if (!(is_string($name) && is_string($credential))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $name,
            $credential,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->authenticatePrincipalSimple($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * createPrincipalToken()
     *   Open an SSO session and return an SSO token to the principal, without
     *   requiring the user's password.
     *   Note that SSO sessions are tied to the supplied user-agent and 
     *   remote IP address.
     * Example: $token = $crowd->createPrincipalToken('foo', 'bar', '192.168.0.55');
     * 
     * @param String $name
     *   The principal's user name.
     * @param String $user agent
     *   The user-agent supplied by the principal to the application
     * @param String $remote_ip_address
     *   The IP address used by principal
     * @return String
     *   The authentication token to give to the principal. 
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to authenticate the principal
     * @throws Services_Atlassian_Crowd_InactiveAccountException
     *   if the principal's account is inactive
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal could not be found
     */
    public function createPrincipalToken ($name, $user_agent, $remote_ip_address)
    { 
        // validate input.
        if (!(is_string($name) && is_string($user_agent) && is_string($remote_ip_address))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $name,
            array(
                array('name'  => 'User-Agent',     'value' => $user_agent),
                array('name'  => 'remote_address', 'value' => $remote_ip_address)
            ),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->createPrincipalToken($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * findAllGroupNames()
     *    List all the Crowd groups that the application has access to.
     * Example: $groups = $crowd->findAllGroupNames();
     * 
     * @return Array
     *   An array of group names
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function findAllGroupNames()
    {
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findAllGroupNames($params);
            return $result->out->string;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * findAllGroupRelationships()
     *
     * @return Array
     *   An array of Crowd group objects.  NB: The group members will not be
     *   populated.
     * 
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function findAllGroupRelationships()
    {
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findAllGroupRelationships($params);
            return $result->out->SOAPNestableGroup;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * findAllPrincipalNames()
     *   List all the Crowd Principals that the application has access to.
     * Example: $principals = $crowd->findAllPrincipalNames();
     * 
     * @return Array
     *   An array of principal names
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function findAllPrincipalNames()
    {
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findAllPrincipalNames($params);
            return $result->out->string;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * findAllRoleNames()
     *   List all the Crowd roles that the application has access to.
     * Example: $roles = $crowd->findAllRoleNames();
     * 
     * @return Array
     *   An array of role names
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function findAllRoleNames()
    {
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findAllRoleNames($params);
            return $result->out->string;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * findGroupByName()
     *   Fetch the group definition for a given group.
     * Example: $group = $crowd->findGroupByName('foo');
     *
     * @param String $groupName
     *   The name of the group.
     * @return Object
     *   A Crowd group object whose name matches the supplied argument
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group was not found
     */   
    public function findGroupByName($groupName)
    {
        // validate the input
        if (!is_string($groupName)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $groupName,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findGroupByName($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * findGroupMemberships()
     *   Fetch a list of the groups that a particular principal is a member of.
     * Example: $groups = $crowd->findGroupMemberships('foo');
     * 
     * @param String $principalName
     *   The name of the principal.
     * @return Array
     *   An array giving the names of each group to which the principal belongs
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function findGroupMemberships($principalName)
    {
        // validate the input
        if (!is_string($principalName)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principalName,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findGroupMemberships($params);
            if (is_array($result->out->string)) {
                return $result->out->string;
            }
            elseif (is_null($result->out->string)) {
                return array();
            }
            else {
                return array($result->out->string);
            }
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }
    

    /**
     * findGroupWithAttributesByName()
     *   Fetch the group definition for a particular group, and return its
     *   extended attribute set (all attributes, not just core attributes).
     * Example: $principal = $crowd->findGroupWithAttributesByName('foo');
     *
     * Added in Crowd 2.0.2
     * @see http://confluence.atlassian.com/display/CROWD/Crowd+2.0.2+Release+Notes
     *
     * @param String $groupName
     *   The name of the group.
     * @return Object
     *   A Crowd group object.
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group could not be found
     */   
    public function findGroupWithAttributesByName($groupName)
    {
        // validate the input
        if (!is_string($groupName)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $groupName,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findGroupWithAttributesByName($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * findPrincipalByName()
     *   Fetch the data associated with a particular principal.
     * Example: $principal = $crowd->findPrincipalByName('foo');
     * 
     * @param String $name
     *   The name of the principal.
     * @return Object
     *   A Crowd principal object
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal could not be found
     */   
    public function findPrincipalByName($name)
    {
        // validate the input
        if (!is_string($name)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $name,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findPrincipalByName($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * findPrincipalWithAttributesByName()
     *   Fetch the data associated with a particular principal, and return their
     *   extended attribute set (all attributes, not just core attributes).
     * Example: $principal = $crowd->findPrincipalWithAttributesByName('foo');
     *
     * Added in Crowd 2.0.2
     * @see http://confluence.atlassian.com/display/CROWD/Crowd+2.0.2+Release+Notes
     * 
     * @param String $name
     *   The name of the principal.
     * @return Object
     *   A Crowd principal object (including detailed attributes)
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal could not be found     
     */   
    public function findPrincipalWithAttributesByName($name)
    {
        // validate the input
        if (!is_string($name)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $name,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findPrincipalWithAttributesByName($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * findPrincipalByToken()
     *   Fetch the data associated with a particular principal, using their SSO 
     *   token.
     * Example: $principal = $crowd->findPrincipalByToken('abcdefghijklmnopqrstuvwxy');
     * 
     * @param String $token
     *   An SSO authentication token.
     * @return Object
     *   A Crowd principal object
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal could not be found
     */   
    public function findPrincipalByToken($token)
    {
        // validate the input
        if (!is_string($token)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $token,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findPrincipalByToken($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * findRoleByName()
     *   Fetch the data associated with a particular role.
     * Example: $role = $crowd->findRoleByName('foo');
     * 
     * @param String $name
     *   A role name.
     * @return Object
     *   A Crowd role object
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the role could not be found
     */   
    public function findRoleByName($name)
    {
        // validate the input
        if (!is_string($name)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $name,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findRoleByName($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * findRoleMemberships()
     *   List the roles that a particular principal has.
     * Example: $roles = $crowd->findRoleMemberships('foo');
     * 
     * @param String $principalName
     *   The name of a Crowd principal.
     * @return Array
     *   An array giving the names of each role the principal has.
     *   If the principal is not found, or has no roles, the array will be empty.
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function findRoleMemberships($principalName)
    {
        // validate the input
        if (!is_string($principalName)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principalName,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->findRoleMemberships($params);
            // always return an array
            if (is_null($result->out->string)) {
                return array();
            }
            elseif (is_string($result->out->string)) {
                return array($result->out->string);
            }
            elseif (is_array($result->out->string)) {
                return $result->out->string;
            }
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }
    

    /**
     * getCacheTime() is deprecated.
     * 
     * @throws Services_Atlassian_Crowd_MethodDeprecatedException
     */
    public function getCacheTime()
    {
        $msg = __FUNCTION__ . ' is deprecated';
        throw new Services_Atlassian_Crowd_MethodDeprecatedException($msg);
    }


    /**
     * getCookieInfo()
     *   Fetch the cookie configuration used by the Crowd server.
     *   Use this when determining how SSO cookies should be served by your app.
     * Example: $cookie_data = $crowd->getCookieInfo();
     *
     * @return Array
     *   Array with keys 'domain' and 'secure'. 
     * 
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function getCookieInfo()
    {
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->getCookieInfo($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * getDomain() is deprecated.
     * 
     * @throws Services_Atlassian_Crowd_MethodDeprecatedException
     */
    public function getDomain()
    {
        $msg = __FUNCTION__ . ' is deprecated';
        throw new Services_Atlassian_Crowd_MethodDeprecatedException($msg);
    }

    /**
     * getGrantedAuthorities()
     *   List the groups that have been given access to connect to the app.
     * Example: $groups = $crowd->getGrantedAuthorities();
     *
     * @return Array
     *   An array of each group name which has permission to connect to the app 
     * 
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function getGrantedAuthorities ()
    {
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->getGrantedAuthorities($params);
            // always return an array
            if (is_null($result->out->string)) {
                return array();
            }
            elseif (is_string($result->out->string)) {
                return array($result->out->string);
            }
            elseif (is_array($result->out->string)) {
                return $result->out->string;
            }
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * invalidatePrincipalToken()
     *   Revoke a principal's SSO token.
     *   Use this when logging out an SSO user.
     * Example: $crowd->invalidatePrincipalToken('abcdefghijklmnopqrstuvxy');
     * 
     * @param String $token
     *   An SSO token.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function invalidatePrincipalToken($token)
    {
        // validate the input
        if (!is_string($token)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $token,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->invalidatePrincipalToken($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * isCacheEnabled()
     *   Discover if the Crowd server is configured to cache data.
     *   Use this to determine if your application may also cache data.
     * Example: $crowd->isCacheEnabled();
     *
     * @return Boolean
     * 
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function isCacheEnabled ()
    {
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(), 
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->isCacheEnabled($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * isGroupMember()
     *   Discover if a principal is a member of a particular group.
     * Example: $crowd->isGroupMember('foo', 'bar');
     * 
     * @param String $group
     *   The name of a Crowd group.
     * @param String $principal
     *   The name of a Crowd principal.
     * @return Boolean
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function isGroupMember($group, $principal)
    {
        // validate the input
        if (!(is_string($group) && is_string($principal))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $group,
            $principal,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->isGroupMember($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * isRoleMember()
     *   Discover if a principal has a particular role.
     * Example: $crowd->isRoleMember('foo', 'bar');
     * 
     * @param String $role
     *   The name of a Crowd role.
     * @param String $principal
     *   The name of a Crowd principal.
     * @return Boolean
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */   
    public function isRoleMember($role, $principal)
    {
        // validate the input
        if (!(is_string($role) && is_string($principal))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $role,
            $principal,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->isRoleMember($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * isValidPrincipalToken()
     *   Check whether an SSO token is valid for a particular remote user.
     *   Use this to authenticate a remote user via SSO instead of via username
     *   and password.
     * Example: $crowd->isValidPrincipalToken('abcdefghijklmnopqrstuwxy', 'foo', '192.168.0.55');
     * 
     * @param String $token
     *   An SSO token (24 characters).
     * @param String $user agent
     *   The user-agent supplied by the principal when authenticating via SSO
     * @param String $remote_ip_address
     *   The IP address used by principal when authenticating via SSO
     * @return String
     *   The authentication token to give to the principal. 
     *
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to check the authenticity
     *   of the principal token
     */
    public function isValidPrincipalToken ($token, $user_agent, $remote_ip_address)
    { 
        // validate input.
        if (!(is_string($token) && strlen($token) == 24 && is_string($user_agent) && is_string($remote_ip_address))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            'token'       => $token,
            'validationFactors' => array(
                array('name'  => 'User-Agent',     'value' => $user_agent),
                array('name'  => 'remote_address', 'value' => $remote_ip_address),
            ),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->isValidPrincipalToken($params);
            return $result->out;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * removeAttributeFromGroup()
     *   Remove an attribute from a particular group.
     * Example: $crowd->removeAttributeFromGroup('foo', 'bar');
     * 
     * @param String $group
     *   The name of a Crowd group
     * @param String $attribute
     *   The name of the attribute to remove.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group is not found
     */
    public function removeAttributeFromGroup ($group, $attribute)
    { 
        // validate input.
        if (!(is_string($group) && is_string($attribute))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $group,
            $attribute,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removeAttributeFromGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }

    /**
     * removeAttributeFromPrincipal()
     *   Remove an attribute from a particular principal.
     * Example: $crowd->removeAttributeFromPrincipal('foo', 'bar');
     * 
     * @param String $principal
     *   The name of a Crowd principal
     * @param String $attribute
     *   The name of the attribute to remove.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the principal
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal is not found
     */
    public function removeAttributeFromPrincipal ($principal, $attribute)
    { 
        // validate input.
        if (!(is_string($principal) && is_string($attribute))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
            $attribute,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removeAttributeFromPrincipal($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * removeGroup()
     *   Delete a group from Crowd.  Note that the group will  be deleted, but 
     *   principals who are members of the group will still exist.
     * Example: $crowd->removeGroup('foo');
     * 
     * @param String $group
     *   The name of a Crowd group
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to remove the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group is not found
     */
    public function removeGroup ($group)
    { 
        // validate input.
        if (!(is_string($group))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $group,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removeGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * removePrincipal()
     *   Delete a principal from Crowd.
     * Example: $crowd->removePrincipal('foo');
     * 
     * @param String $principal
     *   The name of a Crowd principal
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to remove the principal
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal is not found
     */
    public function removePrincipal ($principal)
    { 
        // validate input.
        if (!(is_string($principal))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removePrincipal($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * removePrincipalFromGroup()
     *  Remove a principal from a particular group.
     * Example: $crowd->removePrincipalFromGroup('foo', 'bar');
     * 
     * @param String $principal
     *   The name of a Crowd principal
     * @param String $group
     *   The name of the group to remove from the Principal's account.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to remove the principal 
     *   from the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal or group is not found     
     */
    public function removePrincipalFromGroup ($principal, $group)
    { 
        // validate input.
        if (!(is_string($principal) && is_string($group))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
            $group,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removePrincipalFromGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * removePrincipalFromRole()
     *   Remove a principal from a particular role.
     * Example: $crowd->removePrincipalFromRole('foo', 'bar');
     * 
     * @param String $principal
     *   The name of a Crowd principal
     * @param String $role
     *   The name of the role to remove from the Principal's account.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to remove the principal 
     *   from the role
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal or role is not found
     */
    public function removePrincipalFromRole ($principal, $role)
    { 
        // validate input.
        if (!(is_string($principal) && is_string($role))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
            $role,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removePrincipalFromRole($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * removeRole()
     *   Remove a role from the Crowd directory.
     * Example: $crowd->removeRole('foo');
     *
     * @param String $role
     *   The name of the role to remove.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to remove the role 
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the role is not found
     */
    public function removeRole ($role)
    { 
        // validate input.
        if (!is_string($role)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $role,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->removeRole($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * resetPrincipalCredential()
     *   Reset a principal's password to a random password (created automatically
     *   by Crowd).  Crowd will email the new password to the user.
     * Example: $crowd->resetPrincipalCredential('foo');
     *
     * @param String $principal
     *   The name of the principal whose password should be reset.
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to reset the principal's
     *   password
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal is not found
     * @throws Services_Atlassian_Crowd_Exception
     *   if the principal's email address is not valid in their directory entry
     *   or if Crowd is unable to generate a valid random password
     */
    public function resetPrincipalCredential ($principal)
    { 
        // validate input.
        if (!is_string($principal)) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->resetPrincipalCredential($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * searchGroups()
     *   Search all the groups in the Crowd directory using given criteria.
     *   The key for each search criteria is case-sensitive, the value is case-
     *   insensitive.
     *   String searches are matched against value-contains, boolean searches 
     *   require a value of either 'true' or 'false'.
     * Example: $crowd->searchGroups(array('group.name' => 'bar'));
     * Example: $crowd->searchGroups(array('group.name' => 'foo', 'group.active' => 'true'));
     *
     * @param Array $searchRestrictions
     *   An array of search parameters; each search parameter must be a key-value
     *   pair; both key and value must be strings.
     * @return Array
     *   An array of Crowd group objects
     *
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */
    public function searchGroups ($searchRestrictions) 
    {
        $search = array();
        foreach($searchRestrictions as $key => $value) {
            // validate the input.
            if (!(is_string($key) && is_string($value))) {
                $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
                throw new InvalidArgumentException($msg);               
            }
            // build our search parameters.
            $search[] = array('name' => $key, 'value' => $value);
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $search,  
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->searchGroups($params);
            if(!property_exists($result->out, 'SOAPGroup')) {
                return array();
            }
            elseif(is_array($result->out->SOAPGroup)) {
                return $result->out->SOAPGroup;
            }
            else {
                return array($result->out->SOAPGroup);
            }
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * searchPrincipals()
     *   Search all the principals in the Crowd directory using given criteria.
     *   The key for each search criteria is case-sensitive, the value is case-
     *   insensitive.
     *   String searches are matched against value-contains, boolean searches 
     *   require a value of either 'true' or 'false'.
     * Example: $crowd->searchPrincipals(array('principal.name' => 'foo')); 
     * Example: $crowd->searchPrincipals(array('principal.name' => 'foo', 'principal.active' => 'true'));
     *
     * @param Array $searchRestrictions
     *   The search parameters.
     * @return Array
     *   An array of Crowd principal objects.
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */
    public function searchPrincipals ($searchRestrictions)
    {
        $search = array();
        foreach($searchRestrictions as $key => $value) {
            // validate the input.
            if (!(is_string($key) && is_string($value))) {
                $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
                throw new InvalidArgumentException($msg);               
            }
            // build our search parameters.
            $search[] = array('name' => $key, 'value' => $value);
        }
        
        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $search,  
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->searchPrincipals($params);
            if(!property_exists($result->out, 'SOAPPrincipal')) {
                return array();
            }
            elseif(is_array($result->out->SOAPPrincipal)) {
                return $result->out->SOAPPrincipal;
            }
            else {
                return array($result->out->SOAPPrincipal);
            }
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }       
    }
    
    
    /**
     * searchRoles()
     *   Search all the roles in the Crowd directory using given criteria.
     *   The key for each search criteria is case-sensitive, the value is case-
     *   insensitive.
     *   String searches are matched against value-contains, boolean searches 
     *   require a value of either 'true' or 'false'.
     * Example: $crowd->searchRoles(array('role.name' => 'foo')); 
     * Example: $crowd->searchRoles(array('role.name' => 'foo', 'role.active' => 'true'));
     *
     * @param Array $searchRestrictions
     *   The search parameters.
     * @return Array
     *   An array of Crowd role objects
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     */
    public function searchRoles ($searchRestrictions)
    {
        $search = array();
        foreach($searchRestrictions as $key => $value) {
            // validate the input.
            if (!(is_string($key) && is_string($value))) {
                $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
                throw new InvalidArgumentException($msg);               
            }
            // build our search parameters.
            $search[] = array('name' => $key, 'value' => $value);
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $search,  
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->searchRoles($params);
            if(!property_exists($result->out, 'SOAPRole')) {
                return array();
            }
            elseif(is_array($result->out->SOAPRole)) {
                return $result->out->SOAPRole;
            }
            else {
                return array($result->out->SOAPRole);
            }
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }       
    }


    /**
     * updateGroup()
     *   Update the description or active-flag of a particular group.
     * Example: $crowd->updateGroup('foo', 'bar', FALSE);
     * Example: $crowd->updateGroup('foo', 'bar', TRUE);
     * Example: $crowd->updateGroup('foo', '', FALSE);
     * Example: $crowd->updateGroup('foo', '', TRUE);
     *
     * @param String $name
     *   The name of the group
     * @param String $description
     *   The description for the group
     * @param Boolean $active
     *   Set to TRUE if the group should be enabled
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group is not found
     */
    public function updateGroup ($group, $description, $active)
    { 
        // validate input.
        if (!(is_string($principal) && is_string($description) && is_bool($active))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $group,
            $description, 
            $active,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->updateGroup($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * updateGroupAttribute()
     *   Update the attribute of a particular group.
     * Example: $crowd->updateGroupAttribute('foo', 'bar', 'baz');
     * Example: $crowd->updateGroupAttribute('foo', 'bar', array('baz', 'xzy'));
     *
     * @param String $group
     *   The name of the principal
     * @param String $attribute_name
     *   The attribute to be updated
     * @param String|Array $attribute_value
     *   The new value of the attribute
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the group
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the group is not found
     */
    public function updateGroupAttribute ($group, $attribute_name, $attribute_value)
    { 
        // validate input.
        if (!(is_string($group) && is_string($attribute_name) && (is_string($attribute_value) || is_array($attribute_value)))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
        $this->_getToken(),
        $group,
            array(
                'name' => $attribute_name,
                'values' => is_array($attribute_value) ? $attribute_value : array($attribute_value),
            )
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->updateGroupAttribute($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }


    /**
     * updatePrincipalAttribute()
     *   Update an attribute associated with a particular principal.
     *   The primary details associated with a user are mapped to special 
     *   attribute names (which are case sensitive):
     *   - Email          mail
     *   - First name     givenName
     *   - Last name      sn
     *   - Display name   displayName
     *   If the first name or last name is changed via the Crowd interface, 
     *   Crowd will reset the display name to "Firstname Lastname".
     *   When changing these fields via a remote call, Crowd will not update the
     *   display name field automatically, so you should make an additional 
     *   remote call to update the display name if you wish to follow Crowd's
     *   convention.
     *   
     *   It is not possible to alter the 'active' status of a user via the API.
     *   This feature is currently missing from the Crowd API (as at 2.0.3).
     *
     * Example: $crowd->updatePrincipalAttribute('foo', 'bar', 'baz');
     * Example: $crowd->updatePrincipalAttribute('foo', 'bar', array('baz', 'xzy'));
     *
     * @param String $principal
     *   The name of the principal
     * @param String $attribute_name
     *   The attribute to be updated
     * @param String|Array $attribute_value
     *   The new value of the attribute
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the principal
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal is not found
     */
    public function updatePrincipalAttribute ($principal, $attribute_name, $attribute_value)
    { 
        // validate input.
        if (!(is_string($principal) && is_string($attribute_name) && (is_string($attribute_value) || is_array($attribute_value)))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
        //  throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
            array(
                'name' => $attribute_name,
                'values' => is_array($attribute_value) ? $attribute_value : array($attribute_value),
            ),
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);

        try
        {
            $result = $this->soapClient->updatePrincipalAttribute($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }



    /**
     * updatePrincipalCredential()
     *   Set the password for a particular principal to a chosen value.
     * Example: $crowd->updatePrincipalCredential('foo', 'bar');
     *
     * @param String $principal
     *   The name of the principal
     * @param String $credential
     *   The new password for the user
     * @return Boolean
     *   True on success
     * 
     * @throws InvalidArgumentException
     *   if the supplied arguments are not valid
     * @throws Services_Atlassian_Crowd_InvalidApplicationAuthenticationException
     *   if the application cannot authenticate to Crowd
     * @throws Services_Atlassian_Crowd_ApplicationPermissionException
     *   if the application does not have permission to update the principal
     * @throws Services_Atlassian_Crowd_ObjectNotFoundException
     *   if the principal is not found
     * @throws Services_Atlassian_Crowd_InvalidArgumentException
     *   if the credential is not accepted by Crowd
     */
    public function updatePrincipalCredential ($principal, $credential)
    { 
        // validate input.
        if (!(is_string($principal) && is_string($credential))) {
            $msg = 'Invalid arguments: see function signature for ' . __FUNCTION__;
            throw new InvalidArgumentException($msg);           
        }

        // encode our data into the remote call signature.
        $params = array(
            $this->_getToken(),
            $principal,
            $credential,
        );
        $params = call_user_func_array(array('self', '_soapEncode'), $params);
        
        try
        {
            $result = $this->soapClient->updatePrincipalCredential($params);
            return true;
        }
        catch (SoapFault $e)
        {
            $args = func_get_args();
            return $this->_manageException(__FUNCTION__, $args, $e);
        }
    }




    #############################
    # Private internal functions
    #############################

    /**
     * Authenticate to the application using our internal credentials.
     */ 
    private function _authenticateToServer()
    {
        if (!is_a($this->applicationCredentials, 'Services_Atlassian_Crowd_ApplicationSoapCredentials')) {
            $msg = 'Not configured - application credentials must be provided.';
            throw new RuntimeException($msg);
        }

        // call our authentication function
        $token = $this->authenticateApplication(
            $this->applicationCredentials->application_name,
            $this->applicationCredentials->application_credential);
        // cache our token
        $this->applicationCredentials->application_token = $token;
    }
    
    
    /**
     * Get the application-authentication token.
     * If we don't have one, authenticate to the app using the username and 
     * password.
     */
    private function _getToken()
    {
        // Check that we have a valid authentication token.
        // If not, try to authenticate.
        if (!$this->applicationCredentials->application_token) {
            $this->_authenticateToServer();
        }

        $token = array(
            'name'  => $this->applicationCredentials->application_name,
            'token' => $this->applicationCredentials->application_token,
        );
        return $token;
    }


    /**
     * We catch all Soap faults in our module, and throw more specific faults to the calling application
     * Possible exceptions from the Crowd security server:
     *    EXCEPTION                      Occurances    Description
     *  - ApplicationAccessDeniedException     4   (authenticating principal) The application is not authorised to perform this action (authenticate / validate a principal token).
     *  - ApplicationPermissionException      19   The application does not have the proper permissions to perform this action on the directory server.
     *  - InactiveAccountException             3   (authenticating principal) The principal's account is inactive.
     *  - InvalidAuthenticationException       3   (authenticating principal) The principal's credentials were invalid.
     *  - InvalidAuthenticationException       1   (authenticateApplication) The application's credentials were invalid.
     *  - InvalidAuthorizationTokenException  All  The calling application's applicationToken is invalid
     *  - InvalidCredentialException           3   (add/update/reset principal) The supplied password is invalid.
     *  - InvalidEmailAddressException         1   (resetPrincipalCredential) The supplied email address is invalid
     *  - InvalidGroupException                1   (addGroup) An error occurred adding the group to the directory server
     *  - InvalidRoleException                 1   (addRole) An error occurred adding the role to the directory server
     *  - InvalidTokenException                1   (findPrincipalByToken) Unable to find the specified token
     *  - InvalidUserException                 1   (addPrincipal) The supplied principal is invalid
     *  - ObjectNotFoundException             23   Unable to find the specified group/role/principal. 
     *  - RemoteException
     *
     * We throw 7 custom exceptions:
     *  - Services_Atlassian_Crowd_ServerUnreachableException                 The remote crowd server could not be reached.
     *  - Services_Atlassian_Crowd_InvalidApplicationAuthenticationException  The application's credentials are invalid.
     *  - Services_Atlassian_Crowd_ApplicationPermissionException             Application doesn't have permission to perform the action 
     *  - Services_Atlassian_Crowd_InvalidPrincipalAuthenticationException    The principal's credentials are invalid.
     *  - Services_Atlassian_Crowd_InactiveAccountException                   The principal's account is inactive.
     *  - Services_Atlassian_Crowd_InvalidArgumentException                   One or more of the supplied arguments were not accepted by Crowd.
     *  - Services_Atlassian_Crowd_ObjectNotFoundException                    The principal's credentials are invalid.
     */
    private function _manageException($function_name, $function_args, $soapFault)
    {
        $exception = self::_getCrowdException($soapFault);

        // special case for handling token-authentication failure by the application - we try to reauthenticate.
        // This is because applications can supply cached authentication tokens, which may have expired.
        if ($exception == 'InvalidAuthorizationTokenException') {
            static $retryCount = 0;
            if ($retryCount == 0) {
                $retryCount++;
                $this->_authenticateToServer();
                return call_user_func_array(array($this, $function_name), $function_args);
            }
            // the retries have also failed.
            $msg = 'The Crowd securityServer could not be reached.  Check connection settings and network connectivity.';
            throw new Services_Atlassian_Crowd_ServerUnreachableException($msg);
        }


        // check the soapFault to see if it's a known Crowd error condition
        if ($exception) {
            switch ($exception) {
                // The application doesn't have permission
                case 'ApplicationAccessDeniedException':
                case 'ApplicationPermissionException':
                  $msg = 'The application does not have permission to perform ' . $function_name;
                  throw new Services_Atlassian_Crowd_ApplicationPermissionException($msg);
                  break;

                // The principal's account is inactive
                case 'InactiveAccountException':
                    $msg = 'The principal\'s account is inactive.';
                    throw new Services_Atlassian_Crowd_InactiveAccountException($msg);
                    break;

                // The principal's username/password are invalid
                case 'InvalidAuthenticationException':
                    if ($function_name == 'createPrincipalToken') {
                        $msg = 'The principal could not be found';
                        throw new Services_Atlassian_Crowd_ObjectNotFoundException($msg);
                    }
                    else {
                        $msg = 'The principal\'s username or password is invalid.';
                        throw new Services_Atlassian_Crowd_InvalidPrincipalAuthenticationException($msg);
                    }
                    break;

                // Bad arguments
                case 'InvalidCredentialException':
                case 'InvalidEmailAddressException':
                case 'InvalidGroupException':
                case 'InvalidRoleException':
                case 'InvalidUserException':
                    $msg = 'The supplied arguments were not accepted by Crowd.';
                    throw new Services_Atlassian_Crowd_InvalidArgumentException($msg);
                    break;

                // xxx not found
                case 'InvalidTokenException':
                case 'ObjectNotFoundException':
                    switch ($function_name) {
                        case 'addAttributeToPrincipal':
                        case 'findGroupMemberships':
                        case 'findPrincipalByName':
                        case 'findPrincipalByToken':
                        case 'findPrincipalWithAttributesByName':
                        case 'findRoleMemberships':
                        case 'removePrincipal':
                        case 'removeAttributeFromPrincipal':
                        case 'resetPrincipalCredential':
                        case 'updatePrincipalAttribute':
                        case 'updatePrincipalCredential':
                            $target = 'principal';
                            break;

                        case 'addAttributeToGroup':
                        case 'findGroupByName':
                        case 'findGroupWithAttributesByName':
                        case 'removeAttributeFromGroup':
                        case 'removeGroup':
                        case 'updateGroup':
                        case 'updateGroupAttribute':
                            $target = 'group';
                            break;

                        case 'findRoleByName':
                        case 'removeRole':
                            $target = 'role';
                            break;

                        case 'addPrincipalToGroup':
                        case 'removePrincipalFromGroup':
                            $target = 'principal or group';
                            break;

                        case 'addPrincipalToRole':
                        case 'removePrincipalFromRole':
                            $target = 'principal or role';
                            break;
                    }
                    $msg = "The {$target} was not found.";
                    throw new Services_Atlassian_Crowd_ObjectNotFoundException($msg);
                    break;
            }
        }
        $msg = 'An unknown error occurred.';
        throw new Services_Atlassian_Crowd_Exception($msg);
    }


    /**
     * Crowd's SOAP server expects parameters in the form:
     * array('in0' => $foo, 'in1' => $bar).
     * This helper function automatically encodes arguments into this form.
     */
    private static function _soapEncode()
    {
        $soapData = array();
        foreach(func_get_args() as $index => $arg)
        {
            $soapData["in{$index}"] = $arg;
        }
        return $soapData;
    }

    /**
     * Search a SoapFault exception for the exception code provided by Crowd.
     * This should be the property:
     * $exception->detail->foo (for the exception code 'foo')
     */
    private static function _getCrowdException($exception)
    {
        // Look for the crowd-signature on an exception
        if (property_exists($exception, 'detail')
            && is_object($exception->detail)
            && $keys = array_keys(get_object_vars($exception->detail))
        ) {
            // return the crowd signature if it's found.
            return count($keys) ? array_shift($keys) : FALSE;
        }   
        return FALSE;
    }
}
