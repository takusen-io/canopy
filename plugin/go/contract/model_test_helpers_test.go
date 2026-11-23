package contract

func testServicerModels(models ...string) []*ServicerModelPolicy {
	result := make([]*ServicerModelPolicy, len(models))
	for i, model := range models {
		result[i] = &ServicerModelPolicy{Model: model, MinimumAcceptableBudget: 1}
	}
	return result
}

func testModelBudgets(total uint64, models ...string) []*ModelBudget {
	result := make([]*ModelBudget, len(models))
	remaining := total
	for i, model := range models {
		budget := remaining / uint64(len(models)-i)
		result[i] = &ModelBudget{Model: model, Budget: budget}
		remaining -= budget
	}
	return result
}

func testPricingPolicy() *PricingPolicySnapshot {
	return &PricingPolicySnapshot{Revision: 1}
}
