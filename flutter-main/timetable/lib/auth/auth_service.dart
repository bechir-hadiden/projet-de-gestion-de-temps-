import 'dart:convert';
import 'package:http/http.dart' as http;

class AuthService {
  final String backendUrl = 'http://localhost:3050'; // Replace with your server URL

  // Function to send login request to the backend
  Future<String?> login(String email, String password) async {
    final url = '$backendUrl/login'; // Login endpoint

    final response = await http.post(
      Uri.parse(url),
      headers: {'Content-Type': 'application/json'},
      body: json.encode({'email': email, 'password': password}),
    );

    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      return data['token']; // Return the JWT token
    } else if (response.statusCode == 401) {
      throw Exception('Invalid email or password');
    } else {
      throw Exception('Server error');
    }
  }
}
