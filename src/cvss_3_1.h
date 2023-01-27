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

#ifndef HAVE_CVSS_3_1_H_
#define HAVE_CVSS_3_1_H_

#include <string>

enum class AttackVector {
	Network,
	Adjacent,
	Local,
	Physical
};

enum class AttackComplexity {
	Low,
	High
};

enum class PrivilegesRequired {
	None,
	Low,
	High
};

enum class UserInteraction {
	None,
	Required
};

enum class Scope {
	Unchanged,
	Changed
};

enum class Impact {
	High,
	Low,
	None
};

enum class ExploitCodeMaturity {
	NotDefined,
	High,
	Functional,
	ProofOfConcept,
	Unproven
};

enum class RemediationLevel {
	NotDefined,
	Unavailable,
	Workaround,
	TemporaryFix,
	OfficialFix
};

enum class ReportConfidence {
	NotDefined,
	Confirmed,
	Reasonable,
	Unknown
};

enum class Requirement {
	NotDefined,
	High,
	Medium,
	Low
};

template<typename T> struct Modified {
	T parent;
	bool modified;
};

class CVSS_3_1
{
	private:

	//Base Metrics
	//exploitability
		AttackVector _av; //Attack Vector
		AttackComplexity _ac; //Attack Complexity
		PrivilegesRequired _pr; //Privileges Required
		UserInteraction _ui; //User Interaction
	//scope
		Scope _s; //Scope
	//impact
		Impact _c; //Confidentiality
		Impact _i; //Integrity
		Impact _a; //Availability

	//Temporal Metrics
		ExploitCodeMaturity _e; //Exploit Code Maturity
		RemediationLevel _rl; //Remediation Level
		ReportConfidence _rc; //Report Confidence
	
	//Environmental Metrics
		Requirement _cr; //Confidentiality Requirement
		Requirement _ir; //Integrity Requirement
		Requirement _ar; //Availability Requirement
	//Environmental Modified Bases
		Modified<AttackVector> _mav; //Modified Attack Vector
		Modified<AttackComplexity> _mac; //Modified Attack Complexity
		Modified<PrivilegesRequired> _mpr; //Modified Privileges Required
		Modified<UserInteraction> _mui; //Modified User Interaction
		Modified<Scope> _ms; //Modified Scope
		Modified<Impact> _mc; //Modified Confidentiality
		Modified<Impact> _mi; //Modified Integrity
		Modified<Impact> _ma; //Modified Availability

	//helpers
		float GetImpact(Impact impact);
		float ScoreNormalize(float score);

	public:
		CVSS_3_1(AttackVector av, AttackComplexity ac, PrivilegesRequired pr, UserInteraction ui, Scope s, Impact c, Impact i, Impact a, ExploitCodeMaturity e = ExploitCodeMaturity::NotDefined, RemediationLevel rl = RemediationLevel::NotDefined, ReportConfidence rc = ReportConfidence::NotDefined, Requirement cr = Requirement::NotDefined, Requirement ir = Requirement::NotDefined, Requirement ar = Requirement::NotDefined, Modified<AttackVector> mav = {AttackVector::Network, false}, Modified<AttackComplexity> mac = {AttackComplexity::Low, false}, Modified<PrivilegesRequired> mpr = {PrivilegesRequired::Low, false}, Modified<UserInteraction> mui = {UserInteraction::None, false}, Modified<Scope> ms = {Scope::Unchanged, false}, Modified<Impact> mc = {Impact::High, false}, Modified<Impact> mi = {Impact::High, false}, Modified<Impact> ma = {Impact::High, false});
		float GetAttackVector(bool modified = false);
		float GetAttackComplexity(bool modified = false);
		float GetPrivilegesRequired(bool modified = false);
		float GetUserInteraction(bool modified = false);
		bool GetScopeChanged(bool modified = false);
		float GetConfidentiality(bool modified = false);
		float GetIntegrity(bool modified = false);
		float GetAvailability(bool modified = false);

		float GetExploitCodeMaturity();
		float GetRemediationLevel();
		float GetReportConfidence();

		float GetRequirement(Requirement r);
		float GetConfidentialityRequirement();
		float GetIntegrityRequirement();
		float GetAvailabilityRequirement();

		float GetImpactSubScore(bool modified = false); //ISS
		float GetImpact(bool modified = false); //Final Impact Score
		float GetExploitability(bool modified = false); //Final Exploitability Score
		float GetBaseScore(bool modified = false, bool round = true); //Base Score
		float GetTemporalScore(bool round = true); //Temporal Score
		float GetEnvironmentalScore(bool round = true); //Environmental Score

		void SetAttackVector(AttackVector av, bool modified);
		void SetAttackComplexity(AttackComplexity ac, bool modified);
		void SetPrivilegesRequired(PrivilegesRequired pr, bool modified);
		void SetUserInteraction(UserInteraction ui, bool modified);
		void SetScope(Scope s, bool modified);
		void SetScope(bool changed, bool modified);
		void SetConfidentiality(Impact c, bool modified);
		void SetIntegrity(Impact i, bool modified);
		void SetAvailability(Impact a, bool modified);

};
#endif