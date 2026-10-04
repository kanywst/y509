package cmd

import "testing"

func TestInventoryDaysFieldSaysNever(t *testing.T) {
	if got := daysField(inventoryRow{NoExpiry: true, DaysUntilExpiry: 2900000}); got != "never" {
		t.Errorf("sentinel DAYS = %q, want never", got)
	}
	if got := daysField(inventoryRow{DaysUntilExpiry: 42}); got != "42" {
		t.Errorf("ordinary DAYS = %q, want 42", got)
	}
}
