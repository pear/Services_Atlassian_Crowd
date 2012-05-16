<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Services_Atlassian_Crowd_SecurityServer_Interface specifies the class 
 * interface for a Crowd security server implementation.
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

/**
 * Specify the implementation of a SecurityServer class.
 * This is a PHP-ized specification from the Atlassian spec:
 * @link http://docs.atlassian.com/crowd/current/com/atlassian/crowd/integration/service/soap/server/SecurityServer.html
 */
interface Services_Atlassian_Crowd_SecurityServer_Interface
{
	public function addAttributeToGroup               ($group, $attribute_name, $attribute_value);
	public function addAttributeToPrincipal           ($principal, $attribute_name, $attribute_value);
	public function addGroup                          ($name, $description = '', $active = FALSE);
	public function addPrincipal                      ($name, $credential, $attributes, $active = false);
	public function addPrincipalToGroup               ($principal, $group);
	public function addPrincipalToRole                ($principal, $role);
	public function addRole                           ($role);
	public function authenticateApplication           ($application_name, $application_password);
	public function authenticatePrincipal             ($name, $credential, $user_agent, $remote_ip_address);
	public function authenticatePrincipalSimple       ($name, $credential);
	public function createPrincipalToken              ($name, $user_agent, $remote_ip_address);
	public function findAllGroupNames                 ();
	public function findAllGroupRelationships         ();
    public function findAllPrincipalNames             ();
	public function findAllRoleNames                  ();
	public function findGroupByName                   ($name);
	public function findGroupMemberships              ($principalName);
	public function findGroupWithAttributesByName     ($principalName);
	public function findPrincipalByName               ($name);
	public function findPrincipalByToken              ($token);
	public function findPrincipalWithAttributesByName ($principalName);
	public function findRoleByName                    ($name);
	public function findRoleMemberships               ($principalName) ;
	// public function getCacheTime                      ();  // DEPRECATED - no need to implement
	public function getCookieInfo                     ();
	// public function getDomain                         ();  // DEPRECATED - no need to implement
	public function getGrantedAuthorities             ();
	public function invalidatePrincipalToken          ($token);
	public function isCacheEnabled                    ();
	public function isGroupMember                     ($group, $principal);
	public function isRoleMember                      ($role, $principal);
	public function isValidPrincipalToken             ($token, $user_agent, $remote_ip_address);
	public function removeAttributeFromGroup          ($group, $attribute);
	public function removeAttributeFromPrincipal      ($principal, $attribute);
	public function removeGroup                       ($group);
	public function removePrincipal                   ($principal);
	public function removePrincipalFromGroup          ($principal, $group);
	public function removePrincipalFromRole           ($principal, $role);
	public function removeRole                        ($role);
	public function resetPrincipalCredential          ($principal);
	public function searchGroups                      ($searchRestrictions);
	public function searchPrincipals                  ($searchRestrictions);
	public function searchRoles                       ($searchRestrictions);
	public function updateGroup                       ($group, $description, $active);
	public function updateGroupAttribute              ($group, $attribute_name, $attribute_value);
	public function updatePrincipalAttribute          ($name, $attribute_name, $attribute_value);
	public function updatePrincipalCredential         ($principal, $credential);
}
?>
