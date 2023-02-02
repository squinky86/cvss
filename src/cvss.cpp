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

#include "cvss.h"
#include "cvss_3.h"
#include "cvss_3_1.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace std;

string GetValue(string component)
{
	size_t tmpPos = component.find(":");
	size_t tmpLen = component.length();
	if ((tmpPos != string::npos) && (tmpPos < tmpLen))
	{
		return component.substr(tmpPos + 1);
	}
	return "";
}

int Parse(string const& toParse, bool baseScore, bool temporalScore, bool environmentalScore, bool suppressErrors)
{
	//CVSS 3.1
	AttackVector av = AttackVector::Network;
	AttackComplexity ac = AttackComplexity::Low;
	PrivilegesRequired pr = PrivilegesRequired::None;
	UserInteraction ui = UserInteraction::None;
	Scope s = Scope::Unchanged;
	Impact c = Impact::High;
	Impact i = Impact::High;;
	Impact a = Impact::High;;
	ExploitCodeMaturity e = ExploitCodeMaturity::NotDefined;
	RemediationLevel rl = RemediationLevel::NotDefined;
	ReportConfidence rc = ReportConfidence::NotDefined;
	Requirement cr = Requirement::NotDefined;
	Requirement ir = Requirement::NotDefined;
	Requirement ar = Requirement::NotDefined;
	Modified<AttackVector> mav = { AttackVector::Network, false };
	Modified<AttackComplexity> mac = { AttackComplexity::Low, false };
	Modified<PrivilegesRequired> mpr = { PrivilegesRequired::Low, false };
	Modified<UserInteraction> mui = { UserInteraction::None, false };
	Modified<Scope> ms = { Scope::Unchanged, false };
	Modified<Impact> mc = { Impact::High, false };
	Modified<Impact> mi = { Impact::High, false };
	Modified<Impact> ma = { Impact::High, false };

	string tmpCvssVersion = "3.1";
	vector<string> components;
	size_t start = 0;
	for (size_t pos = toParse.find("/", start); pos != string::npos; pos = toParse.find("/", start))
	{
		components.push_back(toParse.substr(start, pos - start));
		start = pos + 1;
	}
	components.push_back(toParse.substr(start));
	for (auto j : components)
	{
		if (j.rfind("CVSS", 0) == 0) // CVSS Version
		{
			string cvssVersion = GetValue(j);
			if (cvssVersion.rfind("3.1", 0) == 0)
			{
				tmpCvssVersion = "3.1";
				continue;
			}
			else if (cvssVersion.rfind("3.0", 0) == 0)
			{
				tmpCvssVersion = "3.0";
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unsupported CVSS version " << cvssVersion << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("AV:", 0) == 0) // Attack Vector (AV)
		{
			string attackVector = GetValue(j);
			if (attackVector.compare("N") == 0)
			{
				av = AttackVector::Network;
				continue;
			}
			else if (attackVector.compare("A") == 0)
			{
				av = AttackVector::Adjacent;
				continue;
			}
			else if (attackVector.compare("P") == 0)
			{
				av = AttackVector::Physical;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Attack Vector: " << attackVector << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("AC:", 0) == 0) // Attack Complexity (AC)
		{
			string attackComplexity = GetValue(j);
			if (attackComplexity.compare("L") == 0)
			{
				ac = AttackComplexity::Low;
				continue;
			}
			else if (attackComplexity.compare("H") == 0)
			{
				ac = AttackComplexity::High;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Attack Complexity: " << attackComplexity << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("PR:", 0) == 0) // Privileges Required (PR)
		{
			string privilegesRequired = GetValue(j);
			if (privilegesRequired.compare("N") == 0)
			{
				pr = PrivilegesRequired::None;
				continue;
			}
			else if (privilegesRequired.compare("L") == 0)
			{
				pr = PrivilegesRequired::Low;
				continue;
			}
			else if (privilegesRequired.compare("H") == 0)
			{
				pr = PrivilegesRequired::High;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Privileges Required: " << privilegesRequired << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("UI:", 0) == 0) // User Interaction (UI)
		{
			string userInteraction = GetValue(j);
			if (userInteraction.compare("N") == 0)
			{
				ui = UserInteraction::None;
				continue;
			}
			else if (userInteraction.compare("R") == 0)
			{
				ui = UserInteraction::Required;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown User Interaction: " << userInteraction << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("S:", 0) == 0) // Scope (S)
		{
			string scope = GetValue(j);
			if (scope.compare("U") == 0)
			{
				s = Scope::Unchanged;
				continue;
			}
			else if (scope.compare("C") == 0)
			{
				s = Scope::Changed;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Scope: " << scope << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("C:", 0) == 0) // Confidentiality (C)
		{
			string confidentiality = GetValue(j);
			if (confidentiality.compare("H") == 0)
			{
				c = Impact::High;
				continue;
			}
			else if (confidentiality.compare("L") == 0)
			{
				c = Impact::Low;
				continue;
			}
			else if (confidentiality.compare("N") == 0)
			{
				c = Impact::None;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Confidentiality: " << confidentiality << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("I:", 0) == 0) // Integrity (I)
		{
			string integrity = GetValue(j);
			if (integrity.compare("H") == 0)
			{
				i = Impact::High;
				continue;
			}
			else if (integrity.compare("L") == 0)
			{
				i = Impact::Low;
				continue;
			}
			else if (integrity.compare("N") == 0)
			{
				i = Impact::None;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Integrity: " << integrity << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("A:", 0) == 0) // Availability (A)
		{
			string availability = GetValue(j);
			if (availability.compare("H") == 0)
			{
				a = Impact::High;
				continue;
			}
			else if (availability.compare("L") == 0)
			{
				a = Impact::Low;
				continue;
			}
			else if (availability.compare("N") == 0)
			{
				a = Impact::None;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Availability: " << availability << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("E:", 0) == 0) // Exploit Code Maturity (E)
		{
			string exploitMaturity = GetValue(j);
			if (exploitMaturity.compare("X") == 0)
			{
				e = ExploitCodeMaturity::NotDefined;
				continue;
			}
			else if (exploitMaturity.compare("U") == 0)
			{
				e = ExploitCodeMaturity::Unproven;
				continue;
			}
			else if (exploitMaturity.compare("P") == 0)
			{
				e = ExploitCodeMaturity::ProofOfConcept;
				continue;
			}
			else if (exploitMaturity.compare("F") == 0)
			{
				e = ExploitCodeMaturity::Functional;
				continue;
			}
			else if (exploitMaturity.compare("H") == 0)
			{
				e = ExploitCodeMaturity::High;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Exploit Code Maturity: " << exploitMaturity << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("RL:", 0) == 0) // Remediation Level (RL)
		{
			string remediationLevel = GetValue(j);
			if (remediationLevel.compare("X") == 0)
			{
				rl = RemediationLevel::NotDefined;
				continue;
			}
			else if (remediationLevel.compare("O") == 0)
			{
				rl = RemediationLevel::OfficialFix;
				continue;
			}
			else if (remediationLevel.compare("T") == 0)
			{
				rl = RemediationLevel::TemporaryFix;
				continue;
			}
			else if (remediationLevel.compare("W") == 0)
			{
				rl = RemediationLevel::Workaround;
				continue;
			}
			else if (remediationLevel.compare("U") == 0)
			{
				rl = RemediationLevel::Unavailable;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Remediation Level: " << remediationLevel << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("RC:", 0) == 0) // Report Confidence (RC)
		{
			string reportConfidence = GetValue(j);
			if (reportConfidence.compare("X") == 0)
			{
				rc = ReportConfidence::NotDefined;
				continue;
			}
			else if (reportConfidence.compare("U") == 0)
			{
				rc = ReportConfidence::Unknown;
				continue;
			}
			else if (reportConfidence.compare("R") == 0)
			{
				rc = ReportConfidence::Reasonable;
				continue;
			}
			else if (reportConfidence.compare("C") == 0)
			{
				rc = ReportConfidence::Confirmed;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Report Confidence: " << reportConfidence << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("CR:", 0) == 0) // Confidentiality Requirement (CR)
		{
			string confidentialityRequirement = GetValue(j);
			if (confidentialityRequirement.compare("X") == 0)
			{
				cr = Requirement::NotDefined;
				continue;
			}
			if (confidentialityRequirement.compare("H") == 0)
			{
				cr = Requirement::High;
				continue;
			}
			else if (confidentialityRequirement.compare("M") == 0)
			{
				cr = Requirement::Medium;
				continue;
			}
			else if (confidentialityRequirement.compare("L") == 0)
			{
				cr = Requirement::Low;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Confidentiality Requirement: " << confidentialityRequirement << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("IR:", 0) == 0) // Integrity Requirement (IR)
		{
			string integrityRequirement = GetValue(j);
			if (integrityRequirement.compare("X") == 0)
			{
				ir = Requirement::NotDefined;
				continue;
			}
			if (integrityRequirement.compare("H") == 0)
			{
				ir = Requirement::High;
				continue;
			}
			else if (integrityRequirement.compare("M") == 0)
			{
				ir = Requirement::Medium;
				continue;
			}
			else if (integrityRequirement.compare("L") == 0)
			{
				ir = Requirement::Low;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Integrity Requirement: " << integrityRequirement << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("AR:", 0) == 0) // Availability Requirement (AR)
		{
			string availabilityRequirement = GetValue(j);
			if (availabilityRequirement.compare("X") == 0)
			{
				ar = Requirement::NotDefined;
				continue;
			}
			if (availabilityRequirement.compare("H") == 0)
			{
				ar = Requirement::High;
				continue;
			}
			else if (availabilityRequirement.compare("M") == 0)
			{
				ar = Requirement::Medium;
				continue;
			}
			else if (availabilityRequirement.compare("L") == 0)
			{
				ar = Requirement::Low;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Availability Requirement: " << availabilityRequirement << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MAV:", 0) == 0) // Modified Attack Vector (MAV)
		{
			mav.modified = true;
			string attackVector = GetValue(j);
			if (attackVector.compare("X"))
			{
				mav.modified = false;
				continue;
			}
			else if (attackVector.compare("N") == 0)
			{
				mav.parent = AttackVector::Network;
				continue;
			}
			else if (attackVector.compare("A") == 0)
			{
				mav.parent = AttackVector::Adjacent;
				continue;
			}
			else if (attackVector.compare("P") == 0)
			{
				mav.parent = AttackVector::Physical;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified Attack Vector: " << attackVector << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MAC:", 0) == 0) // Modified Attack Complexity (MAC)
		{
			mac.modified = true;
			string attackComplexity = GetValue(j);
			if (attackComplexity.compare("X") == 0)
			{
				mac.modified = false;
				continue;
			}
			else if (attackComplexity.compare("L") == 0)
			{
				mac.parent = AttackComplexity::Low;
				continue;
			}
			else if (attackComplexity.compare("H") == 0)
			{
				mac.parent = AttackComplexity::High;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified Attack Complexity: " << attackComplexity << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MPR:", 0) == 0) // Modified Privileges Required (MPR)
		{
			mpr.modified = true;
			string privilegesRequired = GetValue(j);
			if (privilegesRequired.compare("X") == 0)
			{
				mpr.modified = false;
				continue;
			}
			if (privilegesRequired.compare("N") == 0)
			{
				mpr.parent = PrivilegesRequired::None;
				continue;
			}
			else if (privilegesRequired.compare("L") == 0)
			{
				mpr.parent = PrivilegesRequired::Low;
				continue;
			}
			else if (privilegesRequired.compare("H") == 0)
			{
				mpr.parent = PrivilegesRequired::High;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified Privileges Required: " << privilegesRequired << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MUI:", 0) == 0) // Modified User Interaction (MUI)
		{
			mui.modified = true;
			string userInteraction = GetValue(j);
			if (userInteraction.compare("X") == 0)
			{
				mui.modified = false;
				continue;
			}
			else if (userInteraction.compare("N") == 0)
			{
				mui.parent = UserInteraction::None;
				continue;
			}
			else if (userInteraction.compare("R") == 0)
			{
				mui.parent = UserInteraction::Required;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified User Interaction: " << userInteraction << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MS:", 0) == 0) // Modified Scope (MS)
		{
			ms.modified = true;
			string scope = GetValue(j);
			if (scope.compare("X") == 0)
			{
				ms.modified = false;
				continue;
			}
			else if (scope.compare("U") == 0)
			{
				ms.parent = Scope::Unchanged;
				continue;
			}
			else if (scope.compare("C") == 0)
			{
				ms.parent = Scope::Changed;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified Scope: " << scope << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MC:", 0) == 0) // Modified Confidentiality (MC)
		{
			mc.modified = true;
			string confidentiality = GetValue(j);
			if (confidentiality.compare("X") == 0)
			{
				mc.modified = false;
				continue;
			}
			else if (confidentiality.compare("H") == 0)
			{
				mc.parent = Impact::High;
				continue;
			}
			else if (confidentiality.compare("L") == 0)
			{
				mc.parent = Impact::Low;
				continue;
			}
			else if (confidentiality.compare("N") == 0)
			{
				mc.parent = Impact::None;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified Confidentiality: " << confidentiality << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MI:", 0) == 0) // Modified Integrity (MI)
		{
			mi.modified = true;
			string integrity = GetValue(j);
			if (integrity.compare("X") == 0)
			{
				mi.modified = false;
				continue;
			}
			else if (integrity.compare("H") == 0)
			{
				mi.parent = Impact::High;
				continue;
			}
			else if (integrity.compare("L") == 0)
			{
				mi.parent = Impact::Low;
				continue;
			}
			else if (integrity.compare("N") == 0)
			{
				mi.parent = Impact::None;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Modified Integrity: " << integrity << endl;
				return EXIT_FAILURE;
			}
		}
		else if (j.rfind("MA:", 0) == 0) // Modified Availability (MA)
		{
			ma.modified = true;
			string availability = GetValue(j);
			if (availability.compare("X") == 0)
			{
				ma.modified = false;
				continue;
			}
			else if (availability.compare("H") == 0)
			{
				ma.parent = Impact::High;
				continue;
			}
			else if (availability.compare("L") == 0)
			{
				ma.parent = Impact::Low;
				continue;
			}
			else if (availability.compare("N") == 0)
			{
				ma.parent = Impact::None;
				continue;
			}
			else
			{
				if (!suppressErrors)
					cerr << "Unknown Availability: " << availability << endl;
				return EXIT_FAILURE;
			}
		}
		else
		{
			if (!suppressErrors)
				cerr << "Unknown component: " << j << endl;
			return EXIT_FAILURE;
		}
	}

	CVSS *cvss = nullptr;
	if (tmpCvssVersion.compare("3.0") == 0)
	{
		cvss = new CVSS_3(av, ac, pr, ui, s, c, i, a, e, rl, rc, cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma);
	}
	else if (tmpCvssVersion.compare("3.1") == 0)
	{
		cvss = new CVSS_3_1(av, ac, pr, ui, s, c, i, a, e, rl, rc, cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma);
	}

	if (!cvss)
	{
		return EXIT_FAILURE;
	}

	if (!baseScore && !temporalScore && !environmentalScore)
		baseScore = true;
	
	if (baseScore)
	{
		if (temporalScore || environmentalScore)
			cout << "Base: ";
		cout << cvss->GetBaseScore() << endl;
	}

	if (temporalScore)
	{
		if (baseScore || environmentalScore)
			cout << "Temporal: ";
		cout << cvss->GetTemporalScore() << endl;
	}

	if (environmentalScore)
	{
		if (baseScore || temporalScore)
			cout << "Environmental: ";
		cout << cvss->GetEnvironmentalScore() << endl;
	}

	delete cvss;

	return EXIT_SUCCESS;
}
