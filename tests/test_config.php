<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Services_Atlassian_Crowd tests configuration file.
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

//The values used in tests for the $option array 
global $crowd_options;
$crowd_options = array('app_name' => 'test',
                       'app_credential' => 'test',
                       'service_url' => 'http://localhost:8095/crowd/services/SecurityServer?wsdl',
                       'username' => 'admin',
                       'password' => 'admin',
                       'user_agent' => '',
                       'remote_address' => '127.0.0.1');

if ($fp = @fopen('PHPUnit/Autoload.php', 'r', true)) {
    require_once 'PHPUnit/Autoload.php';
} elseif ($fp = @fopen('PHPUnit/Framework.php', 'r', true)) {
    require_once 'PHPUnit/Framework.php';
    require_once 'PHPUnit/TextUI/TestRunner.php';
} else {
    die('skip could not find PHPUnit');
}
fclose($fp);

require_once 'Services/Atlassian/Crowd.php';
