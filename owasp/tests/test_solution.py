#!/usr/bin/env python3
"""
Test script to verify the solution fixes all vulnerabilities.
This script temporarily renames files to test the solution against the test suite.
"""

import os
import shutil
import subprocess
import sys

def main():
    print("🔧 Testing the solution against the security test suite...")
    
    # Save current working directory
    original_dir = os.getcwd()
    
    try:
        # Change to project directory
        os.chdir('d:/Code/cybersec_aodi')
        
        # Backup original main.py
        if os.path.exists('owasp/main.py'):
            shutil.copy('owasp/main.py', 'owasp/main_vulnerable_backup.py')
            print("✅ Backed up vulnerable main.py")
        
        # Replace main.py with solution
        if os.path.exists('owasp/main_solution.py'):
            shutil.copy('owasp/main_solution.py', 'owasp/main.py')
            print("✅ Replaced main.py with secure solution")
        
        # Remove existing database to start fresh
        if os.path.exists('demo.db'):
            os.remove('demo.db')
            print("✅ Removed old database")
        
        # Run the tests
        print("\n🧪 Running security tests against the solution...")
        result = subprocess.run([
            sys.executable, '-m', 'pytest', 
            'owasp/tests/main_test.py', 
            '-v', '--tb=short'
        ], capture_output=True, text=True)
        
        print("📊 Test Results:")
        print("=" * 60)
        print(result.stdout)
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("🎉 SUCCESS! All security vulnerabilities have been fixed!")
            print("✅ The solution passes all security tests.")
        else:
            print("❌ Some tests are still failing. The solution may need adjustments.")
            
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        
    finally:
        # Restore original main.py
        if os.path.exists('owasp/main_vulnerable_backup.py'):
            shutil.copy('owasp/main_vulnerable_backup.py', 'owasp/main.py')
            os.remove('owasp/main_vulnerable_backup.py')
            print("✅ Restored original vulnerable main.py")
        
        # Restore original directory
        os.chdir(original_dir)
        
        print("\n📚 Files in the project:")
        print("- main.py: Original vulnerable application (for students to fix)")
        print("- main_solution.py: Secure reference implementation")
        print("- tests/main_test.py: Security test suite (all should fail initially)")

if __name__ == "__main__":
    main()