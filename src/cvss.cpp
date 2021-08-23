#include "cvss.h"

#include <algorithm>
#include <cmath>

CVSS::CVSS(AttackVector av, AttackComplexity ac, PrivilegesRequired pr, UserInteraction ui, Scope s, Impact c, Impact i, Impact a, ExploitCodeMaturity e, RemediationLevel rl, ReportConfidence rc, Requirement cr, Requirement ir, Requirement ar, Modified<AttackVector> mav, Modified<AttackComplexity> mac, Modified<PrivilegesRequired> mpr, Modified<UserInteraction> mui, Modified<Scope> ms, Modified<Impact> mc, Modified<Impact> mi, Modified<Impact> ma) :
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

AttackVector CVSS::GetAttackVectorEnum()
{
    return _mav.modified ? _mav.parent : _av;
}

float CVSS::GetAttackVector()
{
    switch (GetAttackVectorEnum())
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

AttackComplexity CVSS::GetAttackComplexityEnum()
{
    return _mac.modified ? _mac.parent : _ac;
}

float CVSS::GetAttackComplexity()
{
    switch (GetAttackComplexityEnum())
    {
    case AttackComplexity::Low:
        return 0.77;
    case AttackComplexity::High:
        return 0.44;
    }
    return 0;
}

PrivilegesRequired CVSS::GetPrivilegesRequiredEnum()
{
    return _mpr.modified ? _mpr.parent : _pr;
}

float CVSS::GetPrivilegesRequired()
{
    switch (GetPrivilegesRequiredEnum())
    {
    case PrivilegesRequired::None:
        return 0.85;
    case PrivilegesRequired::Low:
        return GetScopeChanged() ? 0.68 : 0.62;
    case PrivilegesRequired::High:
        return GetScopeChanged() ? 0.5 : 0.27;
    }
    return 0;
}

UserInteraction CVSS::GetUserInteractionEnum()
{
    return _mui.modified ? _mui.parent : _ui;
}

float CVSS::GetUserInteraction()
{
    switch (GetUserInteractionEnum())
    {
    case UserInteraction::None:
        return 0.85;
    case UserInteraction::Required:
        return 0.62;
    }
    return 0;
}

Scope CVSS::GetScopeEnum()
{
    return _ms.modified ? _ms.parent : _s;
}

bool CVSS::GetScopeChanged()
{
    return _ms.modified ? (_ms.parent == Scope::Changed) : (_s == Scope::Changed);
}

float CVSS::GetImpact(Impact impact)
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

Impact CVSS::GetConfidentialityEnum()
{
    return _mc.modified ? _mc.parent : _c;
}

float CVSS::GetConfidentiality()
{
    return GetImpact(GetConfidentialityEnum());
}

Impact CVSS::GetIntegrityEnum()
{
    return _mi.modified ? _mi.parent : _i;
}

float CVSS::GetIntegrity()
{
    return GetImpact(GetIntegrityEnum());
}

Impact CVSS::GetAvailabilityEnum()
{
    return _ma.modified ? _ma.parent : _a;
}

float CVSS::GetAvailability()
{
    return GetImpact(GetAvailabilityEnum());
}

float CVSS::ScoreNormalize(float score)
{
    return std::min(std::max(score, 0.0f), 10.0f);
}

float CVSS::GetImpactSubScore()
{
    return (1.0 - ((1.0 - GetConfidentiality()) * (1.0 - GetIntegrity()) * (1.0 - GetAvailability())));
}

float CVSS::GetImpact()
{
    float iss = GetImpactSubScore();
    if (GetScopeChanged())
    {
        return ScoreNormalize(7.52 * (iss - 0.029) - (3.25 * pow(iss - 0.02, 15.0)));
    }
    return ScoreNormalize(6.42 * iss);
}

float CVSS::GetExploitability()
{
    return ScoreNormalize(8.22 * GetAttackVector() * GetAttackComplexity() * GetPrivilegesRequired() * GetUserInteraction());
}

float CVSS::GetBaseScore()
{
    if (GetImpact() <= 0.0)
    {
        return 0;
    }
    float factor = GetScopeChanged() ? 1.08 : 1.0;
    return ScoreNormalize(factor * (GetImpact() + GetExploitability()));
}

void CVSS::SetAttackVector(AttackVector av, bool modified)
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

void CVSS::SetAttackComplexity(AttackComplexity ac, bool modified)
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

void CVSS::SetPrivilegesRequired(PrivilegesRequired pr, bool modified)
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

void CVSS::SetUserInteraction(UserInteraction ui, bool modified)
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

void CVSS::SetScope(Scope s, bool modified)
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

void CVSS::SetScope(bool changed, bool modified)
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

void CVSS::SetConfidentiality(Impact c, bool modified)
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

void CVSS::SetIntegrity(Impact i, bool modified)
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

void CVSS::SetAvailability(Impact a, bool modified)
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
