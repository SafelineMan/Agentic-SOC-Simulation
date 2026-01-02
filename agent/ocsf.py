from pydantic import BaseModel, Field, model_validator
from typing import Optional, Dict, Any, List, Union

# --- OCSF Objects ---

class Endpoint(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    mac: Optional[str] = None

class User(BaseModel):
    name: Optional[str] = None
    uid: Optional[str] = None
    domain: Optional[str] = None

class Process(BaseModel):
    name: str
    pid: Optional[int] = None
    ppid: Optional[int] = None
    cmd_line: Optional[str] = None
    path: Optional[str] = None
    user: Optional[User] = None
    parent: Optional['Process'] = None

class File(BaseModel):
    name: str
    path: Optional[str] = None
    hash: Optional[str] = None # SHA256
    size: Optional[int] = None

class Http(BaseModel):
    url: Optional[str] = None
    method: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None

class Dns(BaseModel):
    query: Optional[str] = None
    answers: Optional[List[str]] = None

# --- OCSF Events ---

class OCSFEvent(BaseModel):
    """
    Simplified OCSF Event Schema.
    """
    class_uid: int = Field(..., description="The unique identifier of the event class.")
    class_name: Optional[str] = Field(None, description="The name of the event class (e.g., Process Activity).")
    activity_id: int = Field(..., description="The identifier of the activity (e.g., 1 for Create).")
    activity_name: Optional[str] = Field(None, description="The name of the activity (e.g., Create, Read).")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp.")
    time: Optional[Union[int, str]] = None # Fallback for timestamp
    severity: Optional[str] = "Informational"
    
    # Common Objects
    src_endpoint: Optional[Endpoint] = None
    dst_endpoint: Optional[Endpoint] = None
    actor: Optional[Dict[str, Any]] = None # Usually contains 'process' or 'user'
    
    # Class Specific Objects
    process: Optional[Process] = None
    file: Optional[File] = None
    http_request: Optional[Http] = None
    dns_query: Optional[Dns] = None
    
    raw_data: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = {}

    class Config:
        arbitrary_types_allowed = True

    @model_validator(mode='before')
    @classmethod
    def preprocess_data(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # 1. Handle timestamp/time
            if 'timestamp' not in data and 'time' in data:
                data['timestamp'] = str(data['time'])
            
            # Ensure timestamp is present (default to now if missing)
            if 'timestamp' not in data:
                import datetime
                data['timestamp'] = datetime.datetime.now().isoformat()
                
            # 2. Handle process.user as string
            if 'process' in data and isinstance(data['process'], dict):
                if 'user' in data['process'] and isinstance(data['process']['user'], str):
                    data['process']['user'] = {'name': data['process']['user']}
            
            # 3. Handle actor.user as string (Common OCSF pattern)
            if 'actor' in data and isinstance(data['actor'], dict):
                 if 'user' in data['actor'] and isinstance(data['actor']['user'], str):
                    data['actor']['user'] = {'name': data['actor']['user']}

            # 4. Handle missing class_name/activity_name (Fill with defaults)
            if 'class_name' not in data:
                data['class_name'] = "Unknown"
            if 'activity_name' not in data:
                data['activity_name'] = "Unknown"
                
            # 5. Handle file.name missing (if path exists)
            if 'file' in data and isinstance(data['file'], dict):
                if 'name' not in data['file'] and 'path' in data['file']:
                    # Extract filename from path
                    path = data['file']['path']
                    filename = path.split('\\')[-1].split('/')[-1]
                    data['file']['name'] = filename
                elif 'name' not in data['file']:
                    data['file']['name'] = "unknown_file"

            # 6. Sync actor.process and process (Bidirectional Sync)
            # Case A: actor.process exists, but process is missing -> Copy to process
            if 'actor' in data and isinstance(data['actor'], dict) and 'process' in data['actor']:
                if 'process' not in data:
                    data['process'] = data['actor']['process']
            
            # Case B: process exists, but actor.process is missing -> Copy to actor.process
            elif 'process' in data:
                if 'actor' not in data:
                    data['actor'] = {}
                if isinstance(data['actor'], dict) and 'process' not in data['actor']:
                    data['actor']['process'] = data['process']

        return data
