import os
import sys
from app import app, db
from sqlalchemy import inspect, text

def migrate_database():
    with app.app_context():
        inspector = inspect(db.engine)
        
        # Check if columns exist in users table
        columns = [col['name'] for col in inspector.get_columns('users')]
        
        # Connect to database
        with db.engine.connect() as conn:
            # Add google_id column if it doesn't exist
            if 'google_id' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN google_id VARCHAR(100)'))
                print("Added google_id column to users table")
            
            # Make password column nullable if it's not already
            users_columns = inspector.get_columns('users')
            password_col = next((col for col in users_columns if col['name'] == 'password'), None)
            if password_col and not password_col['nullable']:
                conn.execute(text('ALTER TABLE users ALTER COLUMN password DROP NOT NULL'))
                print("Made password column nullable")
            
            # Add integration fields
            if 'google_connected' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN google_connected BOOLEAN DEFAULT FALSE'))
                print("Added google_connected column to users table")
            
            if 'linkedin_connected' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN linkedin_connected BOOLEAN DEFAULT FALSE'))
                print("Added linkedin_connected column to users table")
            
            if 'dropbox_connected' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN dropbox_connected BOOLEAN DEFAULT FALSE'))
                print("Added dropbox_connected column to users table")
            
            if 'github_connected' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN github_connected BOOLEAN DEFAULT FALSE'))
                print("Added github_connected column to users table")
            
            # Add 2FA fields
            if 'two_factor_enabled' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT FALSE'))
                print("Added two_factor_enabled column to users table")
            
            if 'two_factor_secret' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN two_factor_secret VARCHAR(32)'))
                print("Added two_factor_secret column to users table")
            
            if 'two_factor_backup_codes' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN two_factor_backup_codes TEXT'))
                print("Added two_factor_backup_codes column to users table")
            
            # Add verified column if it doesn't exist
            if 'verified' not in columns:
                conn.execute(text('ALTER TABLE users ADD COLUMN verified BOOLEAN DEFAULT FALSE'))
                print("Added verified column to users table")
            
            conn.commit()
        
        print("Database migration completed successfully!")

if __name__ == '__main__':
    migrate_database()