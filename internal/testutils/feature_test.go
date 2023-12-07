package testutils

import (
	"testing"
)

func TestIgnoreKernelVersionCheckWhenEnvVarIsSet(t *testing.T) {
	tests := []struct {
		name                     string
		toIgnoreNamesEnvValue    string
		testName                 string
		ignoreKernelVersionCheck bool
	}{
		{
			name:                     "should NOT ignore kernel version check if environment var set to empty string",
			toIgnoreNamesEnvValue:    "",
			testName:                 "TestABC",
			ignoreKernelVersionCheck: false,
		},
		{
			name:                     "should ignore kernel version check if environment var set to skip test name with single value",
			toIgnoreNamesEnvValue:    "TestABC",
			testName:                 "TestABC",
			ignoreKernelVersionCheck: true,
		},
		{
			name:                     "should match test name when multiple comma separated names list is provided",
			toIgnoreNamesEnvValue:    "TestABC,TestXYZ",
			testName:                 "TestXYZ",
			ignoreKernelVersionCheck: true,
		},
		{
			name:                     "should NOT match test name when multiple comma separated names list is provided but name is not present in list",
			toIgnoreNamesEnvValue:    "TestABC,TestXYZ",
			testName:                 "TestPQR",
			ignoreKernelVersionCheck: false,
		},
		{
			name:                     "should match test name if names list has leading/trailing spaces",
			toIgnoreNamesEnvValue:    "TestABC, TestXYZ , TestPQR",
			testName:                 "TestXYZ",
			ignoreKernelVersionCheck: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(ignoreKernelVersionEnvVar, tt.toIgnoreNamesEnvValue)

			if got := ignoreKernelVersionCheck(tt.testName); got != tt.ignoreKernelVersionCheck {
				t.Errorf("ignoreKernelVersionCheck() = %v, want %v", got, tt.ignoreKernelVersionCheck)
			}
		})
	}
}
