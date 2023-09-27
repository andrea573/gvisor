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
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
)

type driverVersion struct {
	major int
	minor int
	patch int
}

func driverVersionFrom(version string) (driverVersion, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return driverVersion{}, fmt.Errorf("invalid format of version string %q", version)
	}
	var (
		res driverVersion
		err error
	)
	res.major, err = strconv.Atoi(parts[0])
	if err != nil {
		return driverVersion{}, fmt.Errorf("invalid format for major version %q: %v", version, err)
	}
	res.minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return driverVersion{}, fmt.Errorf("invalid format for minor version %q: %v", version, err)
	}
	res.patch, err = strconv.Atoi(parts[2])
	if err != nil {
		return driverVersion{}, fmt.Errorf("invalid format for patch version %q: %v", version, err)
	}
	return res, nil
}

func (v driverVersion) String() string {
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
}

func (v driverVersion) isGreaterThan(v2 driverVersion) bool {
	return v.isGreaterThanImpl(false /* orEqual */, v2)
}

func (v driverVersion) isGreaterThanOrEqual(v2 driverVersion) bool {
	return v.isGreaterThanImpl(true /* orEqual */, v2)
}

func (v driverVersion) isGreaterThanImpl(orEqual bool, v2 driverVersion) bool {
	if v.major > v2.major {
		return true
	}
	if v.major < v2.major {
		return false
	}
	if v.minor > v2.minor {
		return true
	}
	if v.minor < v2.minor {
		return false
	}
	if v.patch > v2.patch {
		return true
	}
	if v.patch < v2.patch {
		return false
	}
	return orEqual
}

type frontendIoctlHandler func(fi *frontendIoctlState) (uintptr, error)
type controlCmdHandler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54Parameters) (uintptr, error)
type allocationClassHandler func(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64ParametersR535, isNVOS64 bool, isR535 bool) (uintptr, error)
type uvmIoctlHandler func(ui *uvmIoctlState) (uintptr, error)

// ioctlTable is used to hold all ioctl handlers.
//
// The Nvidia ioctl interface branches widely at various places in the kernel
// driver. As for now, versioning is only supported for the following points
// of branching:
//  1. frontend device ioctls (based on IOC_NR(cmd)).
//  2. uvm device ioctls (based on cmd).
//  3. control commands within NV_ESC_RM_CONTROL in frontend device (based on
//     NVOS54_PARAMETERS.Cmd). Note that commands that have RM_GSS_LEGACY_MASK
//     set are not versioned.
//  4. allocation classes within NV_ESC_RM_ALLOC in frontend device (based on
//     NVOS64_PARAMETERS.HClass).
type ioctlTable struct {
	frontendIoctl   map[uint32]frontendIoctlHandler
	uvmIoctl        map[uint32]uvmIoctlHandler
	controlCmd      map[uint32]controlCmdHandler
	allocationClass map[uint32]allocationClassHandler
}

// buildIoctlTable builds an ioctlTable for a given driver version.
func buildIoctlTable(versionStr string) (ioctlTable, error) {
	version, err := driverVersionFrom(versionStr)
	if err != nil {
		return ioctlTable{}, err
	}
	if !version.isGreaterThanOrEqual(baseVersion) {
		return ioctlTable{}, fmt.Errorf("%s is unsupported; minimum supported version is %s", version, baseVersion)
	}

	var res ioctlTable
	for _, cur := range versioningTable {
		if cur.version.isGreaterThan(version) {
			break
		}
		res.apply(cur.handlers)
	}
	return res, nil
}

func (i *ioctlTable) apply(diff ioctlTable) {
	if diff.frontendIoctl != nil {
		if i.frontendIoctl == nil {
			i.frontendIoctl = make(map[uint32]frontendIoctlHandler)
		}
		for k, v := range diff.frontendIoctl {
			if v == nil {
				delete(i.frontendIoctl, k)
			} else {
				i.frontendIoctl[k] = v
			}
		}
	}
	if diff.uvmIoctl != nil {
		if i.uvmIoctl == nil {
			i.uvmIoctl = make(map[uint32]uvmIoctlHandler)
		}
		for k, v := range diff.uvmIoctl {
			if v == nil {
				delete(i.uvmIoctl, k)
			} else {
				i.uvmIoctl[k] = v
			}
		}
	}
	if diff.controlCmd != nil {
		if i.controlCmd == nil {
			i.controlCmd = make(map[uint32]controlCmdHandler)
		}
		for k, v := range diff.controlCmd {
			if v == nil {
				delete(i.controlCmd, k)
			} else {
				i.controlCmd[k] = v
			}
		}
	}
	if diff.allocationClass != nil {
		if i.allocationClass == nil {
			i.allocationClass = make(map[uint32]allocationClassHandler)
		}
		for k, v := range diff.allocationClass {
			if v == nil {
				delete(i.allocationClass, k)
			} else {
				i.allocationClass[k] = v
			}
		}
	}
}

// versionDiff is used to represent the changes made in a given Nvidia driver
// version, compared to the previous entry of such a diff. The diff supports
// three kinds of operations:
//  1. Add: When a non-nil handler is defined and the previous version doesn't
//     have a handler.
//  2. Update: When a non-nil handler is defined and the previous version also
//     defines a handler which will be overwritten.
//  3. Delete: When a nil handler is defined. The previous handler will be
//     deleted if specified.
type versionDiff struct {
	version  driverVersion
	handlers ioctlTable
}

// versioningTable is a sparse version table which stitches various diff
// together (with strictly increasing driver versions). This can be used to
// calculate the resulting ioctl handlers for a given version.
var versioningTable = []versionDiff{
	baseVersionDiff,
	diffR535_43_02,
}

// The base version is the earliest driver version supported by nvproxy. It
// moves with the nvproxy support window.
//
// Currently, the base version is 525.60.13.
var baseVersion = driverVersion{525, 60, 13}

// Since there is no previous diff to compare with, the base diff contains the
// entirety of the nvproxy functionality supported at this version.
var baseVersionDiff = versionDiff{
	version: baseVersion,
	handlers: ioctlTable{
		frontendIoctl: map[uint32]frontendIoctlHandler{
			nvgpu.NV_ESC_CARD_INFO:                     frontendIoctlSimple, // nv_ioctl_card_info_t
			nvgpu.NV_ESC_CHECK_VERSION_STR:             frontendIoctlSimple, // nv_rm_api_version_t
			nvgpu.NV_ESC_SYS_PARAMS:                    frontendIoctlSimple, // nv_ioctl_sys_params_t
			nvgpu.NV_ESC_RM_DUP_OBJECT:                 frontendIoctlSimple, // NVOS55_PARAMETERS
			nvgpu.NV_ESC_RM_SHARE:                      frontendIoctlSimple, // NVOS57_PARAMETERS
			nvgpu.NV_ESC_RM_UNMAP_MEMORY:               frontendIoctlSimple, // NVOS34_PARAMETERS
			nvgpu.NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO: frontendIoctlSimple, // NVOS56_PARAMETERS
			nvgpu.NV_ESC_REGISTER_FD:                   frontendRegisterFD,
			nvgpu.NV_ESC_ALLOC_OS_EVENT:                rmAllocOSEvent,
			nvgpu.NV_ESC_FREE_OS_EVENT:                 rmFreeOSEvent,
			nvgpu.NV_ESC_NUMA_INFO:                     rmNumaInfo,
			nvgpu.NV_ESC_RM_ALLOC_MEMORY:               rmAllocMemory,
			nvgpu.NV_ESC_RM_FREE:                       rmFree,
			nvgpu.NV_ESC_RM_CONTROL:                    rmControl,
			nvgpu.NV_ESC_RM_ALLOC:                      rmAllocR525,
			nvgpu.NV_ESC_RM_VID_HEAP_CONTROL:           rmVidHeapControl,
			nvgpu.NV_ESC_RM_MAP_MEMORY:                 rmMapMemory,
		},
		uvmIoctl: map[uint32]uvmIoctlHandler{
			nvgpu.UVM_INITIALIZE:                     uvmInitialize,
			nvgpu.UVM_DEINITIALIZE:                   uvmIoctlNoParams,
			nvgpu.UVM_CREATE_RANGE_GROUP:             uvmIoctlSimple[nvgpu.UVM_CREATE_RANGE_GROUP_PARAMS],
			nvgpu.UVM_DESTROY_RANGE_GROUP:            uvmIoctlSimple[nvgpu.UVM_DESTROY_RANGE_GROUP_PARAMS],
			nvgpu.UVM_REGISTER_GPU_VASPACE:           uvmIoctlHasRMCtrlFD[nvgpu.UVM_REGISTER_GPU_VASPACE_PARAMS],
			nvgpu.UVM_UNREGISTER_GPU_VASPACE:         uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_VASPACE_PARAMS],
			nvgpu.UVM_REGISTER_CHANNEL:               uvmIoctlHasRMCtrlFD[nvgpu.UVM_REGISTER_CHANNEL_PARAMS],
			nvgpu.UVM_UNREGISTER_CHANNEL:             uvmIoctlSimple[nvgpu.UVM_UNREGISTER_CHANNEL_PARAMS],
			nvgpu.UVM_MAP_EXTERNAL_ALLOCATION:        uvmIoctlHasRMCtrlFD[nvgpu.UVM_MAP_EXTERNAL_ALLOCATION_PARAMS],
			nvgpu.UVM_FREE:                           uvmIoctlSimple[nvgpu.UVM_FREE_PARAMS],
			nvgpu.UVM_REGISTER_GPU:                   uvmIoctlHasRMCtrlFD[nvgpu.UVM_REGISTER_GPU_PARAMS],
			nvgpu.UVM_UNREGISTER_GPU:                 uvmIoctlSimple[nvgpu.UVM_UNREGISTER_GPU_PARAMS],
			nvgpu.UVM_PAGEABLE_MEM_ACCESS:            uvmIoctlSimple[nvgpu.UVM_PAGEABLE_MEM_ACCESS_PARAMS],
			nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION: uvmIoctlSimple[nvgpu.UVM_MAP_DYNAMIC_PARALLELISM_REGION_PARAMS],
			nvgpu.UVM_ALLOC_SEMAPHORE_POOL:           uvmIoctlSimple[nvgpu.UVM_ALLOC_SEMAPHORE_POOL_PARAMS],
			nvgpu.UVM_VALIDATE_VA_RANGE:              uvmIoctlSimple[nvgpu.UVM_VALIDATE_VA_RANGE_PARAMS],
			nvgpu.UVM_CREATE_EXTERNAL_RANGE:          uvmIoctlSimple[nvgpu.UVM_CREATE_EXTERNAL_RANGE_PARAMS],
		},
		controlCmd: map[uint32]controlCmdHandler{
			nvgpu.NV0000_CTRL_CMD_CLIENT_GET_ADDR_SPACE_TYPE:        rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_CLIENT_SET_INHERITED_SHARE_POLICY: rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_GET_ATTACHED_IDS:              rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO:                   rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_GET_ID_INFO_V2:                rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_GET_PROBED_IDS:                rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_ATTACH_IDS:                    rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_DETACH_IDS:                    rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_GET_PCI_INFO:                  rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_QUERY_DRAIN_STATE:             rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_GPU_GET_MEMOP_ENABLE:              rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_SYNC_GPU_BOOST_GROUP_INFO:         rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS:               rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_FABRIC_STATUS:          rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_P2P_CAPS_MATRIX:        rmControlSimple,
			nvgpu.NV0080_CTRL_CMD_FB_GET_CAPS_V2:                    rmControlSimple,
			nvgpu.NV0080_CTRL_CMD_GPU_GET_NUM_SUBDEVICES:            rmControlSimple,
			nvgpu.NV0080_CTRL_CMD_GPU_QUERY_SW_STATE_PERSISTENCE:    rmControlSimple,
			nvgpu.NV0080_CTRL_CMD_GPU_GET_VIRTUALIZATION_MODE:       rmControlSimple,
			0x80028b: rmControlSimple, // unknown, paramsSize == 1
			nvgpu.NV0080_CTRL_CMD_GPU_GET_CLASSLIST_V2:                             rmControlSimple,
			nvgpu.NV0080_CTRL_CMD_HOST_GET_CAPS_V2:                                 rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_INFO:                                 rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_BUS_GET_PCI_BAR_INFO:                             rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_BUS_GET_INFO_V2:                                  rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_BUS_GET_PCIE_SUPPORTED_GPU_ATOMICS:               rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_CE_GET_ALL_CAPS:                                  rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_FB_GET_INFO_V2:                                   rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_INFO_V2:                                  rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_NAME_STRING:                              rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_SHORT_NAME_STRING:                        rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_SIMULATION_INFO:                          rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_QUERY_ECC_STATUS:                             rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_QUERY_COMPUTE_MODE_RULES:                     rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_ACQUIRE_COMPUTE_MODE_RESERVATION:             rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_RELEASE_COMPUTE_MODE_RESERVATION:             rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_GID_INFO:                                 rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_ENGINES_V2:                               rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_ACTIVE_PARTITION_IDS:                     rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GPU_GET_COMPUTE_POLICY_CONFIG:                    rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GET_GPU_FABRIC_PROBE_INFO:                        rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GR_SET_CTXSW_PREEMPTION_MODE:                     rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GR_GET_CTX_BUFFER_SIZE:                           rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GR_GET_GLOBAL_SM_ORDER:                           rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GR_GET_CAPS_V2:                                   rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GR_GET_GPC_MASK:                                  rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GR_GET_TPC_MASK:                                  rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_GSP_GET_FEATURES:                                 rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_MC_GET_ARCH_INFO:                                 rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_MC_SERVICE_INTERRUPTS:                            rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_NVLINK_GET_NVLINK_STATUS:                         rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_PERF_BOOST:                                       rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_RC_GET_WATCHDOG_INFO:                             rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_RC_RELEASE_WATCHDOG_REQUESTS:                     rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_RC_SOFT_DISABLE_WATCHDOG:                         rmControlSimple,
			nvgpu.NV2080_CTRL_CMD_TIMER_GET_GPU_CPU_TIME_CORRELATION_INFO:          rmControlSimple,
			nvgpu.NV503C_CTRL_CMD_REGISTER_VA_SPACE:                                rmControlSimple,
			nvgpu.NV503C_CTRL_CMD_REGISTER_VIDMEM:                                  rmControlSimple,
			nvgpu.NV503C_CTRL_CMD_UNREGISTER_VIDMEM:                                rmControlSimple,
			nvgpu.NV83DE_CTRL_CMD_DEBUG_SET_EXCEPTION_MASK:                         rmControlSimple,
			nvgpu.NV83DE_CTRL_CMD_DEBUG_READ_ALL_SM_ERROR_STATES:                   rmControlSimple,
			nvgpu.NV83DE_CTRL_CMD_DEBUG_CLEAR_ALL_SM_ERROR_STATES:                  rmControlSimple,
			nvgpu.NV906F_CTRL_CMD_RESET_CHANNEL:                                    rmControlSimple,
			nvgpu.NV90E6_CTRL_CMD_MASTER_GET_VIRTUAL_FUNCTION_ERROR_CONT_INTR_MASK: rmControlSimple,
			nvgpu.NVC36F_CTRL_GET_CLASS_ENGINEID:                                   rmControlSimple,
			nvgpu.NVC36F_CTRL_CMD_GPFIFO_GET_WORK_SUBMIT_TOKEN:                     rmControlSimple,
			nvgpu.NVA06C_CTRL_CMD_GPFIFO_SCHEDULE:                                  rmControlSimple,
			nvgpu.NVA06C_CTRL_CMD_SET_TIMESLICE:                                    rmControlSimple,
			nvgpu.NVA06C_CTRL_CMD_PREEMPT:                                          rmControlSimple,
			nvgpu.NV0000_CTRL_CMD_SYSTEM_GET_BUILD_VERSION:                         ctrlClientSystemGetBuildVersion,
			nvgpu.NV0080_CTRL_CMD_FIFO_GET_CHANNELLIST:                             ctrlDevFIFOGetChannelList,
			nvgpu.NV2080_CTRL_CMD_FIFO_DISABLE_CHANNELS:                            ctrlSubdevFIFODisableChannels,
			nvgpu.NV2080_CTRL_CMD_GR_GET_INFO:                                      ctrlSubdevGRGetInfo,
		},
		allocationClass: map[uint32]allocationClassHandler{
			nvgpu.NV01_ROOT:               rmAllocSimple[nvgpu.Handle],
			nvgpu.NV01_ROOT_NON_PRIV:      rmAllocSimple[nvgpu.Handle],
			nvgpu.NV01_ROOT_CLIENT:        rmAllocSimple[nvgpu.Handle],
			nvgpu.NV01_EVENT_OS_EVENT:     rmAllocEventOSEvent,
			nvgpu.NV01_DEVICE_0:           rmAllocSimple[nvgpu.NV0080_ALLOC_PARAMETERS],
			nvgpu.NV20_SUBDEVICE_0:        rmAllocSimple[nvgpu.NV2080_ALLOC_PARAMETERS],
			nvgpu.NV50_THIRD_PARTY_P2P:    rmAllocSimple[nvgpu.NV503C_ALLOC_PARAMETERS],
			nvgpu.GT200_DEBUGGER:          rmAllocSimple[nvgpu.NV83DE_ALLOC_PARAMETERS],
			nvgpu.FERMI_CONTEXT_SHARE_A:   rmAllocSimple[nvgpu.NV_CTXSHARE_ALLOCATION_PARAMETERS],
			nvgpu.FERMI_VASPACE_A:         rmAllocSimple[nvgpu.NV_VASPACE_ALLOCATION_PARAMETERS],
			nvgpu.KEPLER_CHANNEL_GROUP_A:  rmAllocSimple[nvgpu.NV_CHANNEL_GROUP_ALLOCATION_PARAMETERS],
			nvgpu.TURING_CHANNEL_GPFIFO_A: rmAllocSimple[nvgpu.NV_CHANNEL_ALLOC_PARAMS],
			nvgpu.AMPERE_CHANNEL_GPFIFO_A: rmAllocSimple[nvgpu.NV_CHANNEL_ALLOC_PARAMS],
			nvgpu.TURING_DMA_COPY_A:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
			nvgpu.AMPERE_DMA_COPY_A:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
			nvgpu.AMPERE_DMA_COPY_B:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
			nvgpu.HOPPER_DMA_COPY_A:       rmAllocSimple[nvgpu.NVB0B5_ALLOCATION_PARAMETERS],
			nvgpu.TURING_COMPUTE_A:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
			nvgpu.AMPERE_COMPUTE_A:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
			nvgpu.AMPERE_COMPUTE_B:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
			nvgpu.ADA_COMPUTE_A:           rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
			nvgpu.HOPPER_COMPUTE_A:        rmAllocSimple[nvgpu.NV_GR_ALLOCATION_PARAMETERS],
			nvgpu.HOPPER_USERMODE_A:       rmAllocSimple[nvgpu.NV_HOPPER_USERMODE_A_PARAMS],
			nvgpu.GF100_SUBDEVICE_MASTER:  rmAllocNoParams,
			nvgpu.TURING_USERMODE_A:       rmAllocNoParams,
			nvgpu.NV_MEMORY_FABRIC:        rmAllocSimple[nvgpu.NV00F8_ALLOCATION_PARAMETERS],
		},
	},
}

var diffR535_43_02 = versionDiff{
	version: driverVersion{535, 43, 02},
	handlers: ioctlTable{
		frontendIoctl: map[uint32]frontendIoctlHandler{
			nvgpu.NV_ESC_RM_ALLOC: rmAllocR535,
		},
		controlCmd: map[uint32]controlCmdHandler{
			nvgpu.NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES: rmControlSimple,
		},
		allocationClass: map[uint32]allocationClassHandler{
			nvgpu.NV_CONFIDENTIAL_COMPUTE: rmAllocSimple[nvgpu.NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS],
		},
		uvmIoctl: map[uint32]uvmIoctlHandler{
			nvgpu.UVM_MM_INITIALIZE: uvmMMInitialize,
		},
	},
}
