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
 * @copyright 2008 Luca Corbo
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 */

require_once dirname(__FILE__) . '/test_config.php';
/** 
 * Services_Atlassian_Crowd tests
 * 
 * @category  Services
 * @package   Services_Atlassian_Crowd
 * @author    Luca Corbo <lucor@php.net>
 * @copyright 2008 Luca Corbo
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
        $this->_options = $GLOBALS['crowd_options'];
        
    }

    public function tearDown()
    {
        unset($this->crowd);
    }
    
    public function testAll()
    {
        try {
            $this->crowd = new Services_Atlassian_Crowd($this->_options);
        } catch (Services_Atlassian_Crowd_Exception $e) {
            $this->markTestSkipped($e->getMessage());
        }
        
        $this->_token_app = $this->crowd->authenticateApplication();
        
        $this->assertTrue(is_string($this->_token_app));
        $this->_token_user = $this->crowd->authenticatePrincipal($this->_options['username'], 
                                                                 $this->_options['password'],
                                                                 $this->_options['user_agent'], 
                                                                 $this->_options['remote_address']);
        $this->assertTrue(is_string($this->_token_user));
        
        $result = $this->crowd->isValidPrincipalToken($this->_token_user,
                                                      $this->_options['user_agent'], 
                                                      $this->_options['remote_address']);
        $this->assertEquals(true, $result);
        
        $result = $this->crowd->findPrincipalByToken($this->_token_user);
        $this->assertTrue(is_object($result));
        
        $result = $this->crowd->findGroupMemberships($this->_options['username']);
        $this->assertTrue(is_object($result));
        
        $result = $this->crowd->invalidatePrincipalToken($this->_token_user);
        
        $this->assertEquals(true, $result);
        
        $result = $this->crowd->isValidPrincipalToken($this->_token_user,
                                                      $this->_options['user_agent'], 
                                                      $this->_options['remote_address']);
        $this->assertEquals(false, $result);        
    }
}
?>
