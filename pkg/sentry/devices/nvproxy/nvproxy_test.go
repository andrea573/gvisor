// Copyright 2023 The gVisor Authors.
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

package nvproxy

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

func TestVersionTableSorted(t *testing.T) {
	var prev driverVersion // zero value is correct.
	for i, cur := range versioningTable {
		if !cur.version.isGreaterThan(prev) {
			t.Errorf("version %s at index %d is less than or equal to the previous version %s at index %d", cur.version, i, prev, i-1)
		}
		prev = cur.version
	}
}

func TestNVOS21ParamsSize(t *testing.T) {
	if nvgpu.SizeofNVOS21ParametersR535 != nvgpu.SizeofNVOS21Parameters {
		// We assume the size of NVOS21_PARAMETERS struct did not change between
		// R525 and R535. If this turns out to be false, a separate seccomp entry
		// needs to be added for the new size value.
		t.Errorf("SizeofNVOS21ParametersR535(%#08x) != SizeofNVOS21Parameters(%#08x)", nvgpu.SizeofNVOS21ParametersR535, nvgpu.SizeofNVOS21Parameters)
	}
}
