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

#include "cvss_3_1.h"

#include <algorithm>
#include <cmath>

CVSS_3_1::CVSS_3_1(AttackVector av, AttackComplexity ac, PrivilegesRequired pr, UserInteraction ui, Scope s, Impact c, Impact i, Impact a, ExploitCodeMaturity e, RemediationLevel rl, ReportConfidence rc, Requirement cr, Requirement ir, Requirement ar, Modified<AttackVector> mav, Modified<AttackComplexity> mac, Modified<PrivilegesRequired> mpr, Modified<UserInteraction> mui, Modified<Scope> ms, Modified<Impact> mc, Modified<Impact> mi, Modified<Impact> ma) :
	_av(av),
	_ac(ac),
	_pr(pr),
	_ui(ui),
	_s(s),
	_c(c),
	_i(i),
	_a(a),
	_e(e),
	_rl(rl),
	_rc(rc),
	_cr(cr),
	_ir(ir),
	_ar(ar),
	_mav(mav),
	_mac(mac),
	_mpr(mpr),
	_mui(mui),
	_ms(ms),
	_mc(mc),
	_mi(mi),
	_ma(ma)
{
}

float CVSS_3_1::GetAttackVector(bool modified)
{
	switch ((modified && _mav.modified) ? _mav.parent : _av)
	{
	case AttackVector::Network:
		return 0.85;
	case AttackVector::Adjacent:
		return 0.62;
	case AttackVector::Local:
		return 0.55;
	case AttackVector::Physical:
		return 0.2;
	}
	return 0;
}

float CVSS_3_1::GetAttackComplexity(bool modified)
{
	switch ((modified && _mac.modified) ? _mac.parent : _ac)
	{
	case AttackComplexity::Low:
		return 0.77;
	case AttackComplexity::High:
		return 0.44;
	}
	return 0;
}

float CVSS_3_1::GetPrivilegesRequired(bool modified)
{
	switch ((modified && _mpr.modified) ? _mpr.parent : _pr)
	{
	case PrivilegesRequired::None:
		return 0.85;
	case PrivilegesRequired::Low:
		return GetScopeChanged(modified) ? 0.68 : 0.62;
	case PrivilegesRequired::High:
		return GetScopeChanged(modified) ? 0.5 : 0.27;
	}
	return 0;
}

float CVSS_3_1::GetUserInteraction(bool modified)
{
	switch ((modified && _mui.modified) ? _mui.parent : _ui)
	{
	case UserInteraction::None:
		return 0.85;
	case UserInteraction::Required:
		return 0.62;
	}
	return 0;
}

bool CVSS_3_1::GetScopeChanged(bool modified)
{
	return (modified && _ms.modified) ? (_ms.parent == Scope::Changed) : (_s == Scope::Changed);
}

float CVSS_3_1::GetImpact(Impact impact)
{
	switch (impact)
	{
	case Impact::High:
		return 0.56;
	case Impact::Low:
		return 0.22;
	case Impact::None:
		return 0.0;
	}
	return 0;
}

float CVSS_3_1::GetConfidentiality(bool modified)
{
	return (modified && _mc.modified) ? GetImpact(_mc.parent) : GetImpact(_c);
}

float CVSS_3_1::GetIntegrity(bool modified)
{
	return (modified && _mi.modified) ? GetImpact(_mi.parent) : GetImpact(_i);
}

float CVSS_3_1::GetAvailability(bool modified)
{
	return (modified && _ma.modified) ? GetImpact(_ma.parent) : GetImpact(_a);
}

float CVSS_3_1::GetRequirement(Requirement r)
{
	switch (r)
	{
	case (Requirement::High):
		return 1.5;
	case (Requirement::Low):
		return 0.5;
	case (Requirement::Medium):
	case (Requirement::NotDefined):
		return 1.0;
	}
	return 1.0; //should never get here; treat impossible values as not defined
}

float CVSS_3_1::GetConfidentialityRequirement()
{
	return GetRequirement(_cr);
}

float CVSS_3_1::GetIntegrityRequirement()
{
	return GetRequirement(_ir);
}

float CVSS_3_1::GetAvailabilityRequirement()
{
	return GetRequirement(_ar);
}

float CVSS_3_1::GetExploitCodeMaturity()
{
	switch (_e)
	{
	case (ExploitCodeMaturity::Unproven):
		return 0.91;
	case (ExploitCodeMaturity::ProofOfConcept):
		return 0.94;
	case (ExploitCodeMaturity::Functional):
		return 0.97;
	case (ExploitCodeMaturity::High):
	case (ExploitCodeMaturity::NotDefined):
		return 1.0;
	}
	return 1.0;
}

float CVSS_3_1::GetRemediationLevel()
{
	switch (_rl)
	{
	case (RemediationLevel::OfficialFix):
		return 0.95;
	case (RemediationLevel::TemporaryFix):
		return 0.96;
	case (RemediationLevel::Workaround):
		return 0.97;
	case (RemediationLevel::Unavailable):
	case (RemediationLevel::NotDefined):
		return 1.0;
	}
	return 1.0;
}

float CVSS_3_1::GetReportConfidence()
{
	switch (_rc)
	{
	case (ReportConfidence::Unknown):
		return 0.92;
	case (ReportConfidence::Reasonable):
		return 0.96;
	case (ReportConfidence::Confirmed):
	case (ReportConfidence::NotDefined):
		return 1.0;
	}
	return 1.0;
}

float CVSS_3_1::ScoreNormalize(float score)
{
	return std::min(std::max(score, 0.0f), 10.0f);
}

float CVSS_3_1::GetImpactSubScore(bool modified)
{
	if (modified)
	{
 		return std::min((1.0 - ((1.0 - (GetConfidentialityRequirement() * GetConfidentiality(modified))) * (1.0 - (GetIntegrityRequirement() * GetIntegrity(modified))) * (1.0 - (GetAvailabilityRequirement() * GetAvailability(modified))))), 0.915);
	}
	return (1.0 - ((1.0 - GetConfidentiality(modified)) * (1.0 - GetIntegrity(modified)) * (1.0 - GetAvailability(modified))));
}

float CVSS_3_1::GetImpact(bool modified)
{
	float iss = GetImpactSubScore(modified);
	if (GetScopeChanged(modified))
	{
		if (modified)
		{
			return ScoreNormalize(7.52 * (iss - 0.029) - (3.25 * pow(iss * 0.9731 - 0.02, 13.0)));
		}
		return ScoreNormalize(7.52 * (iss - 0.029) - (3.25 * pow(iss - 0.02, 15.0)));
	}
	return ScoreNormalize(6.42 * iss);
}

float CVSS_3_1::GetExploitability(bool modified)
{
	return ScoreNormalize(8.22 * GetAttackVector(modified) * GetAttackComplexity(modified) * GetPrivilegesRequired(modified) * GetUserInteraction(modified));
}

float CVSS_3_1::GetBaseScore(bool modified, bool round)
{
	float impact = GetImpact(modified);
	if (impact <= 0.0)
	{
		return 0;
	}
	float factor = GetScopeChanged(modified) ? 1.08 : 1.0;
	float tmpBase = ScoreNormalize(factor * (impact + GetExploitability(modified)));
	if (round)
		tmpBase = ceil(tmpBase * 10.0) / 10.0;
	return tmpBase;
}

float CVSS_3_1::GetTemporalScore(bool round)
{
	float tmpTemporal = ScoreNormalize(GetBaseScore(false, false) * GetExploitCodeMaturity() * GetRemediationLevel() * GetReportConfidence());
	if (round)
		tmpTemporal = ceil (tmpTemporal * 10.0) / 10.0;
	return tmpTemporal;
}

float CVSS_3_1::GetEnvironmentalScore(bool round)
{
	return GetBaseScore(true);
}

void CVSS_3_1::SetAttackVector(AttackVector av, bool modified)
{
	if (modified)
	{
		_mav.modified = true;
		_mav.parent = av;
	}
	else
	{
		_av = av;
	}
}

void CVSS_3_1::SetAttackComplexity(AttackComplexity ac, bool modified)
{
	if (modified)
	{
		_mac.modified = true;
		_mac.parent = ac;
	}
	else
	{
		_ac = ac;
	}
}

void CVSS_3_1::SetPrivilegesRequired(PrivilegesRequired pr, bool modified)
{
	if (modified)
	{
		_mpr.modified = true;
		_mpr.parent = pr;
	}
	else
	{
		_pr = pr;
	}
}

void CVSS_3_1::SetUserInteraction(UserInteraction ui, bool modified)
{
	if (modified)
	{
		_mui.modified = true;
		_mui.parent = ui;
	}
	else
	{
		_ui = ui;
	}
}

void CVSS_3_1::SetScope(Scope s, bool modified)
{
	if (modified)
	{
		_ms.modified = true;
		_ms.parent = s;
	}
	else
	{
		_s = s;
	}
}

void CVSS_3_1::SetScope(bool changed, bool modified)
{
	if (modified)
	{
		_ms.modified = true;
		_ms.parent = changed ? Scope::Changed : Scope::Unchanged;
	}
	else
	{
		_s = changed ? Scope::Changed : Scope::Unchanged;
	}
}

void CVSS_3_1::SetConfidentiality(Impact c, bool modified)
{
	if (modified)
	{
		_mc.modified = true;
		_mc.parent = c;
	}
	else
	{
		_c = c;
	}
}

void CVSS_3_1::SetIntegrity(Impact i, bool modified)
{
	if (modified)
	{
		_mi.modified = true;
		_mi.parent = i;
	}
	else
	{
		_i = i;
	}
}

void CVSS_3_1::SetAvailability(Impact a, bool modified)
{
	if (modified)
	{
		_ma.modified = true;
		_ma.parent = a;
	}
	else
	{
		_a = a;
	}
}
