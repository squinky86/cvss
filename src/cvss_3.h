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

#ifndef HAVE_CVSS_3_H_
#define HAVE_CVSS_3_H_

#include "cvss_3_1.h"

class CVSS_3 : public CVSS_3_1
{
	public:
		CVSS_3(AttackVector av, AttackComplexity ac, PrivilegesRequired pr, UserInteraction ui, Scope s, Impact c, Impact i, Impact a, ExploitCodeMaturity e = ExploitCodeMaturity::NotDefined, RemediationLevel rl = RemediationLevel::NotDefined, ReportConfidence rc = ReportConfidence::NotDefined, Requirement cr = Requirement::NotDefined, Requirement ir = Requirement::NotDefined, Requirement ar = Requirement::NotDefined, Modified<AttackVector> mav = {AttackVector::Network, false}, Modified<AttackComplexity> mac = {AttackComplexity::Low, false}, Modified<PrivilegesRequired> mpr = {PrivilegesRequired::Low, false}, Modified<UserInteraction> mui = {UserInteraction::None, false}, Modified<Scope> ms = {Scope::Unchanged, false}, Modified<Impact> mc = {Impact::High, false}, Modified<Impact> mi = {Impact::High, false}, Modified<Impact> ma = {Impact::High, false});
		float GetImpact(bool modified = false); //Environmental Score
};

#endif