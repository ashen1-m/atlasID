import React, { useState, useCallback } from 'react';
import { View, Text, StyleSheet, FlatList, TouchableOpacity, RefreshControl, Alert, Modal, TextInput, ScrollView } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { Ionicons } from '@expo/vector-icons';
import { useFocusEffect } from '@react-navigation/native';
import AsyncStorage from '@react-native-async-storage/async-storage';

import VerifierScreen from './src/screens/VerifierScreen';
import CredentialCard from './src/components/CredentialCard';
import { WalletService } from './src/services/WalletService';
import { Colors } from './src/theme/colors';

function WalletScreen() {
  const [credentials, setCredentials] = useState([]);
  const [refreshing, setRefreshing] = useState(false);
  
  const [showForm, setShowForm] = useState(false);
  const [showSyncForm, setShowSyncForm] = useState(false);
  
  const [formData, setFormData] = useState({
    uid: 'mosip-uid-123',
    type: 'Refugee_Status',
    name: 'Yassine',
    origin: 'Morocco'
  });

  const [syncUid, setSyncUid] = useState('mosip-uid-123');

  useFocusEffect(
    useCallback(() => { loadCredentials(); }, [])
  );

  const loadCredentials = async () => {
    setRefreshing(true);
    try {
      await WalletService.syncIssuerConfig();
      const data = await WalletService.getCredentials();
      setCredentials(data);
    } catch (error) {
      // FIX 2: If the network is down or API_URL is wrong, this explicitly warns you
      Alert.alert("Network Error", "Could not reach server to sync offline keys. Check API_URL.");
      console.error(error);
    } finally {
      setRefreshing(false);
    }
  };

  const handleCreateCredential = async () => {
    try {
      await WalletService.issueCredential(
        formData.uid, 
        formData.type, 
        { name: formData.name, origin: formData.origin }
      );
      setShowForm(false);
      loadCredentials();
    } catch (error) {
      Alert.alert("Connection Failed", error.message || "Ensure your backend is running and the IP address is correct.");
    }
  };

  const handleCloudSync = async () => {
    try {
      setRefreshing(true);
      await WalletService.syncFromServer(syncUid);
      setShowSyncForm(false);
      await loadCredentials();
      Alert.alert("Sync Complete", "Credentials safely restored from the Postgres database.");
    } catch (error) {
      Alert.alert("Sync Failed", "Could not find user or connect to database.");
    } finally {
      setRefreshing(false);
    }
  };

  // FIX 1: The New Advanced Trash Button
  const handleAdvancedWipe = () => {
    Alert.alert(
      "Wipe Data",
      "Do you want to clear only this phone's memory, or completely wipe the Cloud Database for this UID too?",
      [
        { text: "Cancel", style: "cancel" },
        { text: "Phone Only", onPress: async () => {
            await AsyncStorage.clear();
            loadCredentials();
          } 
        },
        { text: "Wipe Cloud & Phone", style: "destructive", onPress: async () => {
            try {
              // Nukes the Postgres Database credentials first
              await WalletService.clearCloudDatabase(syncUid); 
              // Then wipes the phone memory
              await AsyncStorage.clear();
              loadCredentials();
              Alert.alert("Nuked", "Cloud database and phone have been wiped clean. You are at 0.");
            } catch (error) {
              Alert.alert("Wipe Failed", "Could not reach the database.");
            }
          }
        }
      ]
    );
  };

  return (
    <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
      <View style={styles.header}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
          <Text style={styles.headerTitle}>Atlas ID Wallet</Text>
          <View style={{ flexDirection: 'row', gap: 16 }}>
            <TouchableOpacity onPress={() => setShowSyncForm(true)}>
              <Ionicons name="cloud-download-outline" size={26} color={Colors.primary} />
            </TouchableOpacity>
            
            {/* The Trash Button now triggers the Advanced Wipe modal */}
            <TouchableOpacity onPress={handleAdvancedWipe}>
              <Ionicons name="trash-outline" size={26} color={Colors.danger} />
            </TouchableOpacity>
          </View>
        </View>
        <Text style={styles.headerSubtitle}>Offline-ready credentials</Text>
      </View>

      <FlatList
        data={credentials}
        keyExtractor={(item, index) => item.id || index.toString()}
        contentContainerStyle={styles.listContent}
        refreshControl={<RefreshControl refreshing={refreshing} tintColor={Colors.primary} />}
        ListEmptyComponent={
          <View style={styles.emptyState}>
            <Ionicons name="wallet-outline" color={Colors.muted} size={48} style={{ marginBottom: 16 }} />
            <Text style={styles.emptyText}>Your wallet is empty.</Text>
            <Text style={styles.emptySubtext}>Tap + to issue, or the Cloud to restore.</Text>
          </View>
        }
        renderItem={({ item }) => <CredentialCard credential={item} />}
      />

      <TouchableOpacity style={styles.fab} onPress={() => setShowForm(true)}>
        <Ionicons name="add" size={32} color="#fff" />
      </TouchableOpacity>

      <Modal visible={showForm} animationType="slide" presentationStyle="pageSheet">
        <View style={styles.modalContainer}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>Request Credential</Text>
            <TouchableOpacity onPress={() => setShowForm(false)}>
              <Ionicons name="close" size={28} color={Colors.text} />
            </TouchableOpacity>
          </View>
          
          <ScrollView style={styles.formContainer}>
            <Text style={styles.inputLabel}>MOSIP UID</Text>
            <TextInput style={styles.input} value={formData.uid} onChangeText={(t) => setFormData({...formData, uid: t})} autoCapitalize="none" autoCorrect={false} />

            <Text style={styles.inputLabel}>Credential Type</Text>
            <TextInput style={styles.input} value={formData.type} onChangeText={(t) => setFormData({...formData, type: t})} />

            <Text style={styles.inputLabel}>Full Name</Text>
            <TextInput style={styles.input} value={formData.name} onChangeText={(t) => setFormData({...formData, name: t})} />

            <Text style={styles.inputLabel}>Country of Origin</Text>
            <TextInput style={styles.input} value={formData.origin} onChangeText={(t) => setFormData({...formData, origin: t})} />

            <TouchableOpacity style={styles.submitBtn} onPress={handleCreateCredential}>
              <Text style={styles.submitBtnText}>Generate & Sign</Text>
            </TouchableOpacity>
          </ScrollView>
        </View>
      </Modal>

      <Modal visible={showSyncForm} animationType="fade" transparent={true}>
        <View style={{flex: 1, backgroundColor: 'rgba(0,0,0,0.5)', justifyContent: 'center', alignItems: 'center'}}>
           <View style={{backgroundColor: Colors.surface, padding: 24, borderRadius: 16, width: '80%'}}>
              <Text style={{fontSize: 20, fontWeight: 'bold', marginBottom: 16}}>Restore Credentials</Text>
              <Text style={{color: Colors.muted, marginBottom: 12}}>Enter your UID to fetch existing IDs from the database.</Text>
              
              <TextInput 
                style={[styles.input, {marginBottom: 20}]} 
                value={syncUid} 
                onChangeText={setSyncUid} 
                autoCapitalize="none"
                autoCorrect={false}
              />
              
              <View style={{flexDirection: 'row', justifyContent: 'space-between'}}>
                 <TouchableOpacity onPress={() => setShowSyncForm(false)} style={{padding: 12}}>
                    <Text style={{color: Colors.danger, fontWeight: 'bold'}}>Cancel</Text>
                 </TouchableOpacity>
                 <TouchableOpacity onPress={handleCloudSync} style={{backgroundColor: Colors.primary, padding: 12, borderRadius: 8}}>
                    <Text style={{color: '#fff', fontWeight: 'bold'}}>Sync Now</Text>
                 </TouchableOpacity>
              </View>
           </View>
        </View>
      </Modal>
    </SafeAreaView>
  );
}

const Tab = createBottomTabNavigator();

export default function App() {
  return (
    <SafeAreaProvider>
      <NavigationContainer>
        <Tab.Navigator
          screenOptions={({ route }) => ({
            headerShown: false,
            tabBarActiveTintColor: Colors.primary,
            tabBarInactiveTintColor: Colors.muted,
            tabBarStyle: { backgroundColor: Colors.surface, borderTopColor: Colors.border, paddingBottom: 5, height: 60 },
            tabBarIcon: ({ color, size }) => {
              let iconName = route.name === 'Wallet' ? 'card' : 'scan-circle';
              return <Ionicons name={iconName} color={color} size={size} />;
            },
          })}
        >
          <Tab.Screen name="Wallet" component={WalletScreen} />
          <Tab.Screen name="Verifier" component={VerifierScreen} />
        </Tab.Navigator>
      </NavigationContainer>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: Colors.background },
  header: { padding: 24, paddingTop: 20, backgroundColor: Colors.surface, borderBottomWidth: 1, borderBottomColor: Colors.border },
  headerTitle: { fontSize: 28, fontWeight: '800', color: Colors.text },
  headerSubtitle: { fontSize: 14, color: Colors.muted, marginTop: 4 },
  listContent: { padding: 20, paddingBottom: 100, flexGrow: 1 }, 
  emptyState: { flex: 1, justifyContent: 'center', alignItems: 'center', marginTop: 80 },
  emptyText: { fontSize: 18, fontWeight: 'bold', color: Colors.text },
  emptySubtext: { fontSize: 14, color: Colors.muted, marginTop: 8 },
  fab: { position: 'absolute', bottom: 20, right: 20, backgroundColor: Colors.primary, width: 60, height: 60, borderRadius: 30, justifyContent: 'center', alignItems: 'center', elevation: 5, shadowColor: '#000', shadowOffset: { width: 0, height: 2 }, shadowOpacity: 0.25, shadowRadius: 3.84 },
  modalContainer: { flex: 1, backgroundColor: Colors.background, paddingTop: 10 },
  modalHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 20, borderBottomWidth: 1, borderBottomColor: Colors.border },
  modalTitle: { fontSize: 22, fontWeight: 'bold', color: Colors.text },
  formContainer: { padding: 20 },
  inputLabel: { fontSize: 14, fontWeight: '600', color: Colors.muted, marginBottom: 6, marginTop: 12 },
  input: { backgroundColor: Colors.surface, borderWidth: 1, borderColor: Colors.border, borderRadius: 8, padding: 14, fontSize: 16, color: Colors.text },
  submitBtn: { backgroundColor: Colors.primary, padding: 16, borderRadius: 8, alignItems: 'center', marginTop: 30, marginBottom: 40 },
  submitBtnText: { color: '#fff', fontSize: 16, fontWeight: 'bold' }
});