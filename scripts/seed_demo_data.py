import sys
import os
import subprocess

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def seed_data():
    print("Seeding demo data into database...")
    script_path = os.path.join(os.path.dirname(__file__), 'generate_demo_traffic.py')
    
    scenarios = [
        ('normal', 200),
        ('port_scan', 50),
        ('repeated_connections', 40),
        ('high_rate', 30)
    ]
    
    for mode, count in scenarios:
        print(f"Generating {count} {mode} events...")
        subprocess.run([sys.executable, script_path, '--mode', mode, '--count', str(count)])
        
    print("Demo data seeding complete.")

if __name__ == '__main__':
    seed_data()
