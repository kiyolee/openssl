#! /usr/bin/env perl
# Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use OpenSSL::Test qw(:DEFAULT bldtop_dir shlib_dir);
use OpenSSL::Test::Simple;
use OpenSSL::Test::Utils;

setup("test_provider");

#$ENV{"OPENSSL_MODULES"} = bldtop_dir("test");
$ENV{OPENSSL_MODULES} = shlib_dir();

simple_test("test_provider", "provider_test");
