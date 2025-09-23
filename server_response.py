from flask import jsonify

def server_response(status_code: int, success: bool, message: str, data=None):
    response = {
        'statusCode': status_code,
        'success': success,
        'message': message,
        'data': data
    }
    return jsonify(response), status_code