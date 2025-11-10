#!/usr/bin/env python3
"""
Verification script to ensure:
1. main.py (vulnerable) fails all tests
2. main_solution.py (secure) passes all tests
"""

import os
import subprocess
import sys
import shutil

def run_tests(file_description):
    """Run pytest and return the result"""
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', 'owasp/tests/main_test.py', '-v', '--tb=line'],
        capture_output=True,
        text=True
    )
    return result

def main():
    os.chdir('d:/Code/cybersec_aodi')
    
    print("=" * 70)
    print("VERIFICATION: Testing both main.py and main_solution.py")
    print("=" * 70)
    
    # Clean up database
    if os.path.exists('demo.db'):
        os.remove('demo.db')
    
    # Test 1: Vulnerable main.py should fail all tests
    print("\n📋 TEST 1: Checking vulnerable main.py (should FAIL all tests)")
    print("-" * 70)
    result1 = run_tests("vulnerable main.py")
    
    failed_count = result1.stdout.count('FAILED')
    passed_count = result1.stdout.count('PASSED')
    
    print(f"Results: {failed_count} failed, {passed_count} passed")
    
    if failed_count == 5 and passed_count == 0:
        print("✅ CORRECT: main.py fails all 5 tests (vulnerabilities present)")
    else:
        print(f"❌ ERROR: Expected 5 failures and 0 passes, got {failed_count} failures and {passed_count} passes")
    
    # Clean database before next test
    if os.path.exists('demo.db'):
        os.remove('demo.db')
    
    # Test 2: Secure main_solution.py should pass all tests
    print("\n📋 TEST 2: Checking secure main_solution.py (should PASS all tests)")
    print("-" * 70)
    
    # Backup vulnerable main.py
    shutil.copy('owasp/main.py', 'owasp/main_temp_backup.py')
    
    # Replace with solution
    shutil.copy('owasp/main_solution.py', 'owasp/main.py')
    
    result2 = run_tests("secure main_solution.py")
    
    failed_count2 = result2.stdout.count('FAILED')
    passed_count2 = result2.stdout.count('PASSED')
    
    print(f"Results: {failed_count2} failed, {passed_count2} passed")
    
    # Restore vulnerable main.py
    shutil.copy('owasp/main_temp_backup.py', 'owasp/main.py')
    os.remove('owasp/main_temp_backup.py')
    
    if failed_count2 == 0 and passed_count2 == 5:
        print("✅ CORRECT: main_solution.py passes all 5 tests (vulnerabilities fixed)")
    else:
        print(f"❌ ERROR: Expected 0 failures and 5 passes, got {failed_count2} failures and {passed_count2} passes")
    
    # Clean up
    if os.path.exists('demo.db'):
        os.remove('demo.db')
    
    # Final summary
    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    
    if failed_count == 5 and passed_count == 0 and failed_count2 == 0 and passed_count2 == 5:
        print("✅ SUCCESS: Both files work correctly!")
        print("   - main.py: 5 failures (vulnerable - students must fix)")
        print("   - main_solution.py: 5 passes (secure reference implementation)")
        return 0
    else:
        print("❌ FAILURE: Something is wrong with the test setup")
        print(f"   - main.py: {failed_count} failures, {passed_count} passes")
        print(f"   - main_solution.py: {failed_count2} failures, {passed_count2} passes")
        return 1

if __name__ == "__main__":
    sys.exit(main())
