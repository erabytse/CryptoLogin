/**
 * CryptoLogin Mobile Example - React Native
 * Demonstrates mobile integration with CryptoLogin
 */
import React, { useState } from 'react';
import {
  StyleSheet,
  Text,
  View,
  TextInput,
  Button,
  Alert,
  ScrollView,
  SafeAreaView,
} from 'react-native';
import { createClient, deriveUserId } from 'cryptologin-client';

// Configuration
const API_URL = 'https://api.docudeeper.com/api/v1';

// Initialize CryptoLogin client
const client = createClient({
  baseURL: API_URL,
  timeout: 30000,
});

export default function App() {
  const [masterSecret, setMasterSecret] = useState('');
  const [status, setStatus] = useState('Ready');
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(false);

  const validateSecret = (secret) => {
    if (secret.length < 32) {
      Alert.alert('Error', 'Master secret must be at least 32 characters');
      return false;
    }
    return true;
  };

  const handleRegister = async () => {
    if (!validateSecret(masterSecret)) return;
    
    setLoading(true);
    setStatus('Registering...');
    
    try {
      const userId = await client.register(masterSecret, {
        device: 'mobile',
        platform: 'react-native',
      });
      
      setStatus(`✅ Registered: ${userId.substring(0, 16)}...`);
      Alert.alert('Success', 'User registered successfully');
    } catch (error) {
      setStatus(`❌ Error: ${error.message}`);
      Alert.alert('Error', error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!validateSecret(masterSecret)) return;
    
    setLoading(true);
    setStatus('Logging in...');
    
    try {
      const sessionData = await client.login(masterSecret);
      setSession(sessionData);
      setStatus(`✅ Logged in: ${sessionData.sessionId.substring(0, 16)}...`);
      Alert.alert('Success', 'Login successful');
    } catch (error) {
      setStatus(`❌ Error: ${error.message}`);
      Alert.alert('Error', error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    setStatus('Logging out...');
    
    try {
      await client.logout();
      setSession(null);
      setStatus('👋 Logged out');
      Alert.alert('Success', 'Logged out successfully');
    } catch (error) {
      setStatus(`❌ Error: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Text style={styles.title}>🔐 CryptoLogin</Text>
          <Text style={styles.subtitle}>Mobile Example</Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.label}>Master Secret</Text>
          <TextInput
            style={styles.input}
            placeholder="Enter your master secret (min 32 chars)"
            secureTextEntry
            value={masterSecret}
            onChangeText={setMasterSecret}
            editable={!loading}
          />
          <Text style={styles.hint}>
            🔒 This secret never leaves your device
          </Text>
        </View>

        <View style={styles.statusCard}>
          <Text style={styles.statusText}>{status}</Text>
        </View>

        <View style={styles.buttonContainer}>
          {!session ? (
            <>
              <Button
                title="Register"
                onPress={handleRegister}
                disabled={loading}
              />
              <View style={styles.spacer} />
              <Button
                title="Login"
                onPress={handleLogin}
                disabled={loading}
              />
            </>
          ) : (
            <>
              <View style={styles.sessionInfo}>
                <Text style={styles.sessionLabel}>Session ID:</Text>
                <Text style={styles.sessionValue}>
                  {session.sessionId.substring(0, 32)}...
                </Text>
                <Text style={styles.sessionLabel}>Expires:</Text>
                <Text style={styles.sessionValue}>
                  {new Date(session.expiresAt).toLocaleString()}
                </Text>
              </View>
              <Button
                title="Logout"
                onPress={handleLogout}
                disabled={loading}
                color="#FF5252"
              />
            </>
          )}
        </View>

        <View style={styles.footer}>
          <Text style={styles.footerText}>
            Powered by CryptoLogin v2.1.5
          </Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#24323A',
  },
  scrollContent: {
    padding: 20,
  },
  header: {
    alignItems: 'center',
    marginBottom: 30,
  },
  title: {
    fontSize: 32,
    fontWeight: 'bold',
    color: '#F5F5F5',
  },
  subtitle: {
    fontSize: 16,
    color: '#D8D8DD',
    marginTop: 5,
  },
  card: {
    backgroundColor: '#2c474d',
    padding: 20,
    borderRadius: 12,
    marginBottom: 20,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    color: '#F5F5F5',
    marginBottom: 10,
  },
  input: {
    backgroundColor: '#1a2329',
    padding: 15,
    borderRadius: 8,
    color: '#F5F5F5',
    fontSize: 16,
    borderWidth: 2,
    borderColor: '#A2F3EB',
  },
  hint: {
    fontSize: 12,
    color: '#D8D8DD',
    marginTop: 8,
  },
  statusCard: {
    backgroundColor: '#2c474d',
    padding: 15,
    borderRadius: 12,
    marginBottom: 20,
    borderLeftWidth: 4,
    borderLeftColor: '#00D4FF',
  },
  statusText: {
    fontSize: 14,
    color: '#F5F5F5',
  },
  buttonContainer: {
    marginBottom: 20,
  },
  spacer: {
    height: 10,
  },
  sessionInfo: {
    backgroundColor: '#2c474d',
    padding: 15,
    borderRadius: 12,
    marginBottom: 15,
  },
  sessionLabel: {
    fontSize: 12,
    color: '#D8D8DD',
    marginTop: 10,
  },
  sessionValue: {
    fontSize: 14,
    color: '#F5F5F5',
    fontFamily: 'monospace',
  },
  footer: {
    alignItems: 'center',
    marginTop: 30,
  },
  footerText: {
    fontSize: 12,
    color: '#D8D8DD',
  },
});