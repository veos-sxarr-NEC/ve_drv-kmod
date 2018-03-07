#!/bin/sh
#
# Vector Engine Driver
#
# Copyright (C) 2017-2018 NEC Corporation
# This file is part of VE Driver.
#
# VE Driver is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# VE Driver is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with the VE Driver; if not, see
# <http://www.gnu.org/licenses/>.
#

grep '^[0-9]' "$1" | (
while read nr decoder;
do
	echo "SENSOR_VALUE_SHOW(${nr}, ${decoder});";
	echo "SENSOR_VALUE_STORE(${nr});";
	echo "static SENSOR_DEVICE_ATTR(${nr});";
done
) > sensor.h

grep '^[0-9]' "$1" | (
echo "static struct attribute *sensor_attrs[] = {"
while read nr decoer;
do
	echo "	&dev_attr_sensor_${nr}.attr,";
done
echo "	NULL,"
echo "};"
echo "static struct attribute_group sensor_attribute_group = {"
echo "	.attrs = sensor_attrs"
echo "};"
) >> sensor.h
