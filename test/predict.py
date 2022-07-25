import os
try:
    from sklearn.externals import joblib
except:
    os.system("pip install scikit-learn==0.20.3")
    os.system("pip install sklearn")
    os.system("pip install joblib==0.16.0")

try:
    import simplejson
except:
    os.system("pip install simplejson")

try:
    import xgboost
except:
    os.system("pip install xgboost==1.1.1")

try:
    import pandas as pd
except:
    os.system("pip install pandas")

current_path = os.path.abspath(os.path.dirname(__file__))
#input
with open(current_path + "/input.txt", "r", encoding = 'utf-8') as f:
    input_json = f.read()
input_dict = simplejson.loads(input_json)
print(input_dict)


input_variables={'gender':input_dict['gender'], 'age':74, 'vasopressin':0, 'urineoutput': 1736.0,
    'heartrate_mean':70.76,'sysbp_mean':122.4, 'diasbp_mean':49.88,
    'resprate_mean':14.96, 'tempc_mean':36.37 , 'spo2_mean':95.4,
    'baseexcess_mean':3.8, 'totalco2_mean':25.94, 'calcium_mean':1.13,
    'lactate_mean':2.3,'pco2_mean':38.83, 'ph_mean':7.42, 'po2_mean':177.88,
    'coronary heart disease.csv':0, 'diabetes.csv':0, 'family history of stroke.csv':0,
    'creatinine.csv_mean':0.66,'glucose.csv_mean':108.06, 'platelet.csv_mean':198.93,
    'potassium.csv_mean':3.88,'sodium.csv_mean':139.66, 'urea nitrogen.csv_mean':20.47,
    'WBC.csv_mean':9.71, 'aniongap':9.00,'bicarbonate':22.5, 'hematocrit':25.00,
    'hemoglobin':8.6, 'ptt':43.80, 'inr':1.25, 'pt':14.40, 'BMI':24.41}

print(input_variables)


1/0
#load models
model_mortality=joblib.load(current_path + '/hospital_mortality_XGB.model')
model_septic_shock=joblib.load(current_path + '/septic_shock_XGB.model')
model_liver_dysfunction=joblib.load(current_path + '/liver_dysfunction_XGB.model')
model_thrombocytopenia=joblib.load(current_path + '/thrombocytopenia_XGB.model')

#dispose
input_variables=pd.DataFrame(input_variables,index = [0])
septic_shock=model_septic_shock.predict_proba(input_variables)
liver_dysfunction=model_liver_dysfunction.predict_proba(input_variables)
thrombocytopenia=model_thrombocytopenia.predict_proba(input_variables)
mortality=model_mortality.predict_proba(input_variables)

#output
output_variables={'mortality':mortality[0,1],
    'septic shock':septic_shock[0,1],
    'liver dysfunction':liver_dysfunction[0,1],
    'thrombocytopenia':thrombocytopenia[0,1]}

#with open(current_path + "/output.txt", "w", encoding = 'utf-8') as f:
#    f.write(str(output_variables))

print("process completed")






with open(current_path + "/output.txt", "w", encoding = 'utf-8') as f:
    f.write(str(input_dict))


