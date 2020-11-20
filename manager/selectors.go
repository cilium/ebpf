package manager

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// OneOf - This selector is used to ensure that at least of a list of probe selectors is valid. In other words, this
// can be used to ensure that at least one of a list of optional probes is activated.
type OneOf struct {
	Selectors []ProbesSelector
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (oo *OneOf) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	var l []ProbeIdentificationPair
	for _, selector := range oo.Selectors {
		l = append(l, selector.GetProbesIdentificationPairList()...)
	}
	return l
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (oo *OneOf) RunValidator(manager *Manager) error {
	var errs []string
	for _, selector := range oo.Selectors {
		if err := selector.RunValidator(manager); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) == len(oo.Selectors) {
		return errors.Errorf(
			"OneOf requirement failed, none of the following probes are running [%s]",
			strings.Join(errs, " | "))
	}
	// at least one selector was successful
	return nil
}

func (oo *OneOf) String() string {
	var strs []string
	for _, id := range oo.GetProbesIdentificationPairList() {
		str := fmt.Sprintf("%s", id)
		strs = append(strs, str)
	}
	return strings.Join(strs, ", ")
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// now select the new one
func (oo *OneOf) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	for _, selector := range oo.Selectors {
		selector.EditProbeIdentificationPair(old, new)
	}
}

// AllOf - This selector is used to ensure that all the proves in the provided list are running.
type AllOf struct {
	Selectors []ProbesSelector
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (ao *AllOf) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	var l []ProbeIdentificationPair
	for _, selector := range ao.Selectors {
		l = append(l, selector.GetProbesIdentificationPairList()...)
	}
	return l
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (ao *AllOf) RunValidator(manager *Manager) error {
	var errMsg []string
	for _, selector := range ao.Selectors {
		if err := selector.RunValidator(manager); err != nil {
			errMsg = append(errMsg, err.Error())
		}
	}
	if len(errMsg) > 0 {
		return errors.Errorf(
			"AllOf requirement failed, the following probes are not running [%s]",
			strings.Join(errMsg, " | "))
	}
	// no error means that all the selectors were successful
	return nil
}

func (ao *AllOf) String() string {
	var strs []string
	for _, id := range ao.GetProbesIdentificationPairList() {
		str := fmt.Sprintf("%s", id)
		strs = append(strs, str)
	}
	return strings.Join(strs, ", ")
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// now select the new one
func (ao *AllOf) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	for _, selector := range ao.Selectors {
		selector.EditProbeIdentificationPair(old, new)
	}
}

// BestEffort - This selector is used to load probes in best effort mode
type BestEffort struct {
	Selectors []ProbesSelector
}

// GetProbesIdentificationPairList - Returns the list of probes that this selector activates
func (be *BestEffort) GetProbesIdentificationPairList() []ProbeIdentificationPair {
	var l []ProbeIdentificationPair
	for _, selector := range be.Selectors {
		l = append(l, selector.GetProbesIdentificationPairList()...)
	}
	return l
}

// RunValidator - Ensures that the probes that were successfully activated follow the selector goal.
// For example, see OneOf.
func (be *BestEffort) RunValidator(manager *Manager) error {
	return nil
}

func (be *BestEffort) String() string {
	var strs []string
	for _, id := range be.GetProbesIdentificationPairList() {
		str := fmt.Sprintf("%s", id)
		strs = append(strs, str)
	}
	return strings.Join(strs, ", ")
}

// EditProbeIdentificationPair - Changes all the selectors looking for the old ProbeIdentificationPair so that they
// now select the new one
func (be *BestEffort) EditProbeIdentificationPair(old ProbeIdentificationPair, new ProbeIdentificationPair) {
	for _, selector := range be.Selectors {
		selector.EditProbeIdentificationPair(old, new)
	}
}
