// Code generated by counterfeiter. DO NOT EDIT.
package licensefakes

import (
	"sync"

	"k8s.io/release/pkg/license"
)

type FakeDownloaderImplementation struct {
	GetLicensesStub        func() (*license.SPDXLicenseList, error)
	getLicensesMutex       sync.RWMutex
	getLicensesArgsForCall []struct {
	}
	getLicensesReturns struct {
		result1 *license.SPDXLicenseList
		result2 error
	}
	getLicensesReturnsOnCall map[int]struct {
		result1 *license.SPDXLicenseList
		result2 error
	}
	SetOptionsStub        func(*license.DownloaderOptions)
	setOptionsMutex       sync.RWMutex
	setOptionsArgsForCall []struct {
		arg1 *license.DownloaderOptions
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeDownloaderImplementation) GetLicenses() (*license.SPDXLicenseList, error) {
	fake.getLicensesMutex.Lock()
	ret, specificReturn := fake.getLicensesReturnsOnCall[len(fake.getLicensesArgsForCall)]
	fake.getLicensesArgsForCall = append(fake.getLicensesArgsForCall, struct {
	}{})
	stub := fake.GetLicensesStub
	fakeReturns := fake.getLicensesReturns
	fake.recordInvocation("GetLicenses", []interface{}{})
	fake.getLicensesMutex.Unlock()
	if stub != nil {
		return stub()
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeDownloaderImplementation) GetLicensesCallCount() int {
	fake.getLicensesMutex.RLock()
	defer fake.getLicensesMutex.RUnlock()
	return len(fake.getLicensesArgsForCall)
}

func (fake *FakeDownloaderImplementation) GetLicensesCalls(stub func() (*license.SPDXLicenseList, error)) {
	fake.getLicensesMutex.Lock()
	defer fake.getLicensesMutex.Unlock()
	fake.GetLicensesStub = stub
}

func (fake *FakeDownloaderImplementation) GetLicensesReturns(result1 *license.SPDXLicenseList, result2 error) {
	fake.getLicensesMutex.Lock()
	defer fake.getLicensesMutex.Unlock()
	fake.GetLicensesStub = nil
	fake.getLicensesReturns = struct {
		result1 *license.SPDXLicenseList
		result2 error
	}{result1, result2}
}

func (fake *FakeDownloaderImplementation) GetLicensesReturnsOnCall(i int, result1 *license.SPDXLicenseList, result2 error) {
	fake.getLicensesMutex.Lock()
	defer fake.getLicensesMutex.Unlock()
	fake.GetLicensesStub = nil
	if fake.getLicensesReturnsOnCall == nil {
		fake.getLicensesReturnsOnCall = make(map[int]struct {
			result1 *license.SPDXLicenseList
			result2 error
		})
	}
	fake.getLicensesReturnsOnCall[i] = struct {
		result1 *license.SPDXLicenseList
		result2 error
	}{result1, result2}
}

func (fake *FakeDownloaderImplementation) SetOptions(arg1 *license.DownloaderOptions) {
	fake.setOptionsMutex.Lock()
	fake.setOptionsArgsForCall = append(fake.setOptionsArgsForCall, struct {
		arg1 *license.DownloaderOptions
	}{arg1})
	stub := fake.SetOptionsStub
	fake.recordInvocation("SetOptions", []interface{}{arg1})
	fake.setOptionsMutex.Unlock()
	if stub != nil {
		fake.SetOptionsStub(arg1)
	}
}

func (fake *FakeDownloaderImplementation) SetOptionsCallCount() int {
	fake.setOptionsMutex.RLock()
	defer fake.setOptionsMutex.RUnlock()
	return len(fake.setOptionsArgsForCall)
}

func (fake *FakeDownloaderImplementation) SetOptionsCalls(stub func(*license.DownloaderOptions)) {
	fake.setOptionsMutex.Lock()
	defer fake.setOptionsMutex.Unlock()
	fake.SetOptionsStub = stub
}

func (fake *FakeDownloaderImplementation) SetOptionsArgsForCall(i int) *license.DownloaderOptions {
	fake.setOptionsMutex.RLock()
	defer fake.setOptionsMutex.RUnlock()
	argsForCall := fake.setOptionsArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeDownloaderImplementation) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getLicensesMutex.RLock()
	defer fake.getLicensesMutex.RUnlock()
	fake.setOptionsMutex.RLock()
	defer fake.setOptionsMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeDownloaderImplementation) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ license.DownloaderImplementation = new(FakeDownloaderImplementation)
