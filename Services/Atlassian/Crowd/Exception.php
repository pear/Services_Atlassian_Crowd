<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Exception used to incidate a problem authenticating to the Crowd server.
 *
 * Services_Atlassian_Crowd is a package to use Atlassian Crowd from PHP
 *
 * PHP version 5
 * 
 * Copyright (C) 2008 Infinite Campus Inc., Luca Corbo
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
 * @copyright 2008 Infinite Campus Inc., Luca Corbo
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 */

/**
 * PEAR Exception handler and base class
 */
require_once 'PEAR/Exception.php';

/**
 * Services_Atlassian_Crowd_Exception
 *
 * @category  Services
 * @package   Services_Atlassian_Crowd
 * @author    Infinite Campus, Inc.
 * @author    Luca Corbo <lucor@php.net>
 * @copyright 2008 Infinite Campus Inc., Luca Corbo
 * @license   http://www.apache.org/licenses/LICENSE-2.0 Apache License
 * @link      http://pear.php.net/packages/Services_Atlassian_Crowd
 */
class Services_Atlassian_Crowd_Exception extends PEAR_Exception
{
}
?>