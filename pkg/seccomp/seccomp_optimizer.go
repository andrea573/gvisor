// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package seccomp

// ruleOptimizerFunc is a function type that can optimize a SyscallRule.
// It returns the updated SyscallRule, along with whether any modification
// was made.
type ruleOptimizerFunc func(SyscallRule) (SyscallRule, bool)

// convertSingleOrRuleToThatRule replaces `Or` rules with a single branch
// to just that branch.
func convertSingleOrRuleToThatRule(rule SyscallRule) (SyscallRule, bool) {
	if orRule, isOr := rule.(Or); isOr && len(orRule) == 1 {
		return orRule[0], true
	}
	return rule, false
}

// convertSingleAndRuleToThatRule replaces `And` rules with a single branch
// to just that branch.
func convertSingleAndRuleToThatRule(rule SyscallRule) (SyscallRule, bool) {
	if andRule, isAnd := rule.(And); isAnd && len(andRule) == 1 {
		return andRule[0], true
	}
	return rule, false
}

// flattenOrRules turns Ors embedded inside an Or rule into a flat Or rule.
func flattenOrRules(rule SyscallRule) (SyscallRule, bool) {
	orRule, isOr := rule.(Or)
	if !isOr {
		return rule, false
	}
	anySubOr := false
	for _, subRule := range orRule {
		if _, subIsOr := subRule.(Or); subIsOr {
			anySubOr = true
			break
		}
	}
	if !anySubOr {
		return rule, false
	}
	var newRules []SyscallRule
	for _, subRule := range orRule {
		if subOr, subIsOr := subRule.(Or); subIsOr {
			newRules = append(newRules, subOr...)
		} else {
			newRules = append(newRules, subRule)
		}
	}
	return Or(newRules), true
}

// flattenAndRules turns Ands embedded inside an And rule into a flat And
// rule.
func flattenAndRules(rule SyscallRule) (SyscallRule, bool) {
	andRule, isAnd := rule.(And)
	if !isAnd {
		return rule, false
	}
	anySubAnd := false
	for _, subRule := range andRule {
		if _, subIsAnd := subRule.(And); subIsAnd {
			anySubAnd = true
			break
		}
	}
	if !anySubAnd {
		return rule, false
	}
	var newRules []SyscallRule
	for _, subRule := range andRule {
		if subAnd, subIsAnd := subRule.(And); subIsAnd {
			newRules = append(newRules, subAnd...)
		} else {
			newRules = append(newRules, subRule)
		}
	}
	return And(newRules), true
}

// convertMatchAllOrXToMatchAll an Or rule that contains MatchAll to MatchAll.
func convertMatchAllOrXToMatchAll(rule SyscallRule) (SyscallRule, bool) {
	orRule, isOr := rule.(Or)
	if !isOr {
		return rule, false
	}
	for _, subRule := range orRule {
		if _, subIsMatchAll := subRule.(MatchAll); subIsMatchAll {
			return MatchAll{}, true
		}
	}
	return orRule, false
}

// convertMatchAllAndXToX removes MatchAll clauses from And rules.
func convertMatchAllAndXToX(rule SyscallRule) (SyscallRule, bool) {
	andRule, isAnd := rule.(And)
	if !isAnd {
		return rule, false
	}
	hasMatchAll := false
	for _, subRule := range andRule {
		if _, subIsMatchAll := subRule.(MatchAll); subIsMatchAll {
			hasMatchAll = true
			break
		}
	}
	if !hasMatchAll {
		return rule, false
	}
	var newRules []SyscallRule
	for _, subRule := range andRule {
		if _, subIsAny := subRule.(MatchAll); !subIsAny {
			newRules = append(newRules, subRule)
		}
	}
	if len(newRules) == 0 {
		// An `And` rule with zero rules inside is invalid.
		return MatchAll{}, true
	}
	return And(newRules), true
}

// optimizeSyscallRuleFuncs losslessly optimizes a SyscallRule using the given
// optimization functions.
// Optimizers should be ranked in order of importance, with the most
// important first.
// An optimizer will be exhausted before the next one is ever run.
// Earlier optimizers are re-exhausted if later optimizers cause change.
func optimizeSyscallRuleFuncs(rule SyscallRule, funcs []ruleOptimizerFunc) SyscallRule {
	for changed := true; changed; {
		for _, fn := range funcs {
			rule.Recurse(func(subRule SyscallRule) SyscallRule {
				return optimizeSyscallRuleFuncs(subRule, funcs)
			})
			if rule, changed = fn(rule); changed {
				break
			}
		}
	}
	return rule
}

// optimizeSyscallRule losslessly optimizes a `SyscallRule`.
func optimizeSyscallRule(rule SyscallRule) SyscallRule {
	return optimizeSyscallRuleFuncs(rule, []ruleOptimizerFunc{
		convertSingleOrRuleToThatRule,
		convertSingleAndRuleToThatRule,
		flattenOrRules,
		flattenAndRules,
		convertMatchAllOrXToMatchAll,
		convertMatchAllAndXToX,
	})
}
