<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Services_Atlassian_Crowd tests
 *
 * PHP version 5
 * 
 * Copyright (C) 2008 Luca Corbo
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
 * @author    Luca Corbo <lucor@php.net>
 * @author    Marcus Deglos <marcus@deglos.com>
 * @copyright 2010 Marcus Deglos
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 */

//Remove the comment below if you want test from source
set_include_path('../../..'.PATH_SEPARATOR.get_include_path());


require_once 'PHPUnit/Framework.php';
require_once 'Services/Atlassian/Crowd.php';
require_once '_test_config.inc.php';

/** 
 * Services_Atlassian_Crowd tests
 * 
 * @category  Services
 * @package   Services_Atlassian_Crowd
 * @author    Luca Corbo <lucor@php.net>
 * @author    Marcus Deglos <marcus@deglos.com>
 * @copyright 2010 Marcus Deglos
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 */
class ServicesAtlassianCrowdTest extends PHPUnit_Framework_TestCase
{

    private $crowd = null;
    private $_options;
    private $_token_app;
    private $_token_user;
    
    public function setUp()
    {
        // create a connection object
        $this->_options = $GLOBALS['crowd_options'];
    }

    public function tearDown()
    {
        unset($this->crowd);
    }
    
    public function testAll()
    {
        $credentials = new Services_Atlassian_Crowd_ApplicationSoapCredentials(
        	$this->_options['service_url'],
        	$this->_options['app_name'],
        	$this->_options['app_credential']
    	);
        $this->crowd = new Services_Atlassian_Crowd($credentials);
        
        // get an authentication token
        $this->_token_app = $this->crowd->authenticateApplication(
            $this->_options['app_name'],
            $this->_options['app_credential']
            );
        $this->assertTrue(is_string($this->_token_app));
        
        // authenticate a principal
        $this->_token_user = $this->crowd->authenticatePrincipal($this->_options['username'], 
                                                                 $this->_options['password'],
                                                                 $this->_options['user_agent'], 
                                                                 $this->_options['remote_address']);
        $this->assertTrue(is_string($this->_token_user));
        

        // check that the token we received is valid
        $result = $this->crowd->isValidPrincipalToken($this->_token_user,
                                                      $this->_options['user_agent'], 
                                                      $this->_options['remote_address']);
        $this->assertEquals(true, $result);

        // test searching by token        
        $result = $this->crowd->findPrincipalByToken($this->_token_user);
        $this->assertTrue(is_object($result));
        
        // test listing group membership
        $result = $this->crowd->findGroupMemberships($this->_options['username']);
        $this->assertTrue(is_array($result));
        
        // test revoking a token
        $result = $this->crowd->invalidatePrincipalToken($this->_token_user);
        $this->assertEquals(true, $result);
        
        // test that the token is revoked
        $result = $this->crowd->isValidPrincipalToken($this->_token_user,
                                                      $this->_options['user_agent'], 
                                                      $this->_options['remote_address']);
        $this->assertEquals(false, $result);        
    }
}
?>
