import 'package:flutter/material.dart';
import '/auth/login_page.dart'; // Import LoginPage
import '/auth/auth_utils.dart'; // Import authentication check
import 'room.dart'; // Import your Pages like Rooms, Teachers, etc.
import 'teachers.dart'; // Import the TeachersPage
import 'subjects.dart'; // Import the SubjectsPage
import 'classes.dart'; // Import the ClassesPage
import 'sessions.dart'; // Import the SessionsPage
import 'students.dart'; // Import the StudentsPage
import 'timetable.dart'; // Import the TimetablePage

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Button Navigator',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.blue),
        useMaterial3: true,
      ),
      routes: {
        '/login': (context) => const LoginPage(),
        '/main': (context) => const HomePage(), // Home page after login
      },
      home: FutureBuilder<bool>(
        future: isAuthenticated(), // Check if authenticated
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }

          if (snapshot.data == true) {
            return const HomePage(); // Show HomePage if authenticated
          } else {
            return const LoginPage(); // Show LoginPage if not authenticated
          }
        },
      ),
    );
  }
}

// HomePage that contains your button navigation
class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Home')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            _buildButton(context, 'Rooms', const RoomsPage()),
            _buildButton(context, 'Teachers', const TeachersPage()),
            _buildButton(context, 'Subjects', const SubjectsPage()),
            _buildButton(context, 'Classes', const ClassesPage()),
            _buildButton(context, 'Sessions', const SessionsPage()),
            _buildButton(context, 'Students', const StudentsPage()),
            _buildButton(context, 'Timetable', const TimetablePage()),
          ],
        ),
      ),
    );
  }

  Widget _buildButton(BuildContext context, String title, Widget targetPage) {
    return ElevatedButton(
      onPressed: () {
        Navigator.push(
          context,
          MaterialPageRoute(builder: (context) => targetPage),
        );
      },
      child: Text(title),
    );
  }
}
//  print('Token: $token');