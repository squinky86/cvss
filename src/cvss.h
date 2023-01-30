/*
CVSS
Copyright (C) 2023 Jon Hood <jwh0011@auburn.edu>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program; if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef HAVE_CVSS_H_
#define HAVE_CVSS_H_

#include <string>

class CVSS
{
	public:

		virtual float GetBaseScore(bool modified = false, bool round = true) {return 0;}; //Base Score
		virtual float GetTemporalScore(bool round = true) {return 0;}; //Temporal Score
		virtual float GetEnvironmentalScore(bool round = true) {return 0;}; //Environmental Score
};
#endif