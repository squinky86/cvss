#ifndef HAVE_CVSS_H_
#define HAVE_CVSS_H_

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

class CVSS
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
	//Environmentall Modified Bases
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
		CVSS(AttackVector av, AttackComplexity ac, PrivilegesRequired pr, UserInteraction ui, Scope s, Impact c, Impact i, Impact a, ExploitCodeMaturity e = ExploitCodeMaturity::NotDefined, RemediationLevel rl = RemediationLevel::NotDefined, ReportConfidence rc = ReportConfidence::NotDefined, Requirement cr = Requirement::NotDefined, Requirement ir = Requirement::NotDefined, Requirement ar = Requirement::NotDefined, Modified<AttackVector> mav = {AttackVector::Network, false}, Modified<AttackComplexity> mac = {AttackComplexity::Low, false}, Modified<PrivilegesRequired> mpr = {PrivilegesRequired::Low, false}, Modified<UserInteraction> mui = {UserInteraction::None, false}, Modified<Scope> ms = {Scope::Unchanged, false}, Modified<Impact> mc = {Impact::High, false}, Modified<Impact> mi = {Impact::High, false}, Modified<Impact> ma = {Impact::High, false});
		AttackVector GetAttackVectorEnum();
		float GetAttackVector();
		AttackComplexity GetAttackComplexityEnum();
		float GetAttackComplexity();
		PrivilegesRequired GetPrivilegesRequiredEnum();
		float GetPrivilegesRequired();
		UserInteraction GetUserInteractionEnum();
		float GetUserInteraction();
		Scope GetScopeEnum();
		bool GetScopeChanged();
		Impact GetConfidentialityEnum();
		float GetConfidentiality();
		Impact GetIntegrityEnum();
		float GetIntegrity();
		Impact GetAvailabilityEnum();
		float GetAvailability();

		float GetImpactSubScore(); //ISS
		float GetImpact(); //Final Impact Score
		float GetExploitability(); //Final Exploitability Score
		float GetBaseScore(); //Base Score

		void SetAttackVector(AttackVector av, bool modified = false);
		void SetAttackComplexity(AttackComplexity ac, bool modified = false);
		void SetPrivilegesRequired(PrivilegesRequired pr, bool modified = false);
		void SetUserInteraction(UserInteraction ui, bool modified = false);
		void SetScope(Scope s, bool modified = false);
		void SetScope(bool changed, bool modified = false);
		void SetConfidentiality(Impact c, bool modified = false);
		void SetIntegrity(Impact i, bool modified = false);
		void SetAvailability(Impact a, bool modified = false);

};
#endif
