<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */


/**
 * Services_Atlassian_Crowd_Exception
 *
 * @category  Services
 * @package   Services_Atlassian_Crowd
 * @author    Marcus Deglos <marcus@deglos.com>
 * @copyright 2010 Marcus Deglos
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 */

// inherit from the standard PEAR exception
require_once '/usr/share/php/PEAR/Exception.php';

/**
 * Base exception for all Crowd-originating exceptions.
 */



class Services_Atlassian_Crowd_Exception extends PEAR_Exception
{
}
class Services_Atlassian_Crowd_ServerUnreachableException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_InvalidApplicationAuthenticationException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_ApplicationPermissionException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_InvalidPrincipalAuthenticationException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_InactiveAccountException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_InvalidArgumentException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_ObjectNotFoundException extends Services_Atlassian_Crowd_Exception
{
}
class Services_Atlassian_Crowd_MethodDeprecatedException extends Services_Atlassian_Crowd_Exception
{
}


?>
