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

#include "cvss_3.h"

#include <cmath>

CVSS_3::CVSS_3(AttackVector av, AttackComplexity ac, PrivilegesRequired pr, UserInteraction ui, Scope s, Impact c, Impact i, Impact a, ExploitCodeMaturity e, RemediationLevel rl, ReportConfidence rc, Requirement cr, Requirement ir, Requirement ar, Modified<AttackVector> mav, Modified<AttackComplexity> mac, Modified<PrivilegesRequired> mpr, Modified<UserInteraction> mui, Modified<Scope> ms, Modified<Impact> mc, Modified<Impact> mi, Modified<Impact> ma) : CVSS_3_1(av, ac, pr, ui, s, c, i, a, e, rl, rc, cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma)
{
}

float CVSS_3::GetImpact(bool modified)
{
	float iss = GetImpactSubScore(modified);
	if (GetScopeChanged(modified))
	{
		return ScoreNormalize(7.52 * (iss - 0.029) - (3.25 * pow(iss - 0.02, 15.0)));
	}
	return ScoreNormalize(6.42 * iss);
}
