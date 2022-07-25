import psycopg2
from scipy import stats
import matplotlib.pyplot as plt
import datetime
import pandas as pd
from scipy import stats
import numpy as np
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import GridSearchCV


# a function to search and download tables from PSQL
def search_table(s='*', f='admissions', w='', download=''):
    temp = s.lower()
    for i in temp:
        if i > "z" or i < "a":
            assert "TypeError"
    del temp
    conn = psycopg2.connect(database="mimic", user="postgres",
                            password="pandora", host="127.0.0.1", port="5432")
    cursor = conn.cursor()
    if w != '':
        cursor.execute("select " + s + " from mimiciii." + f + ' where ' + w)
    else:
        cursor.execute("select " + s + " from mimiciii." + f)
    table = cursor.fetchall()
    colnames = [desc[0] for desc in cursor.description]
    columns = cursor.fetchall()
    cursor.close()
    conn.close()
    columns = pd.DataFrame(columns)
    table = pd.DataFrame(table)
    table.columns = colnames
    if download != '':
        table.to_csv('download data/' + download + '.csv', index=False)
    return table


# some functions to convert time into hours
def calculate_time(x):
    if x == 'nan':
        return 'NaN'
    else:
        curTime = datetime.datetime.strptime(x, '%Y-%m-%d %H:%M:%S')
        utcTime2 = datetime.datetime.strptime("1970-01-01 00:00:00", '%Y-%m-%d %H:%M:%S')
        metTime = curTime - utcTime2
        timeStamp = metTime.days * 24 * 3600 + metTime.seconds
        return (timeStamp / 3600 + 87600 + 72)


def transform_time(dataframe, column_name):
    dataframe[column_name + '_h'] = dataframe[column_name].apply(lambda x: calculate_time(str(x)))


# use winsorize to deal with outlier
def winsorize(data, percentage_one=0.01, percentage_two=0.99, show=False):
    if show == True:
        plt.figure(figsize=(5, 5), dpi=300)
        ax1 = plt.subplot(121)
        plt.hist(data, bins=100)
    count1 = len(data)
    lower_bound = data.quantile(percentage_one)
    upper_bound = data.quantile(percentage_two)
    count2 = len(data[data < lower_bound]) + len(data[data > upper_bound])
    data[data < lower_bound] = lower_bound
    data[data > upper_bound] = upper_bound

    if show == True:
        print('', data.name, ':\n', 'lower bound is', lower_bound, '\n',
              'upeer bound is', upper_bound, '\n',
              'totally dealt with', count2, 'of', count1, '(', (count2 / count1) * 100, '%)', '\n')
        ax2 = plt.subplot(122)
        plt.hist(data, bins=100)


# by using regression to fill Nan
def fill(dataframe, variables_list, variables_y, parameters, model, show=False):
    for i in variables_y:
        if show == True:
            plt.figure(figsize=(10, 10), dpi=300)
            ax1 = plt.subplot(121)
            plt.hist(dataframe[i], bins=100)
        clf = GridSearchCV(model, parameters, cv=5)
        X = dataframe[dataframe[i].notnull()][variables_list]
        y = dataframe[dataframe[i].notnull()][i]
        clf.fit(X, y)
        scores = clf.score(X, y)
        # scores = cross_val_score(estimator=model, X=dataframe[variables_list], y=dataframe['hospital_mortality'], cv=5,scoring = "neg_mean_absolute_error")
        # train_score=model.score(dataframe[variables_list], dataframe['hospital_mortality'])

        print('the best model is:', clf.best_estimator_, 'with best score', clf.best_score_)
        print('mean test scores are', clf.cv_results_['mean_test_score'])
        fillX = dataframe[dataframe[i].isnull()][variables_list]
        dataframe.loc[dataframe[dataframe[i].isnull()].index, i] = clf.predict(fillX)
        if show == True:
            ax2 = plt.subplot(122)
            plt.hist(dataframe[i], bins=100)
            plt.show()


# k-s test
def ksTest(dataframe, variables, show=''):
    for i in variables:
        res = stats.kstest(dataframe[dataframe[i].notnull()][i], 'norm')
        print(i, ':', res)
        if (show != '') & (i == show):
            plt.hist(dataframe[i], bins=50)
            plt.show()


# t-test
def tTest(dataframe, variables, groupby, show=''):
    for i in variables:
        group1 = dataframe[(dataframe[groupby] == 1) & (dataframe[i].notnull())][i]
        group2 = dataframe[(dataframe[groupby] == 0) & (dataframe[i].notnull())][i]
        res = stats.ttest_ind(group1, group2)
        print(i, ':', res)
        if (show != '') & (i == show):
            fig = plt.figure(figsize=(5, 5), dpi=300)
            ax1 = fig.add_subplot(111)
            ax1.hist([group1, group2], bins=50)
            plt.show()


# chi-square test
def chi2Test(dataframe, variables_x, variable_y, show=False):
    for i in variables_x:
        count = 0
        row = len(dataframe[i].unique())
        column = len(dataframe[variable_y].unique())
        chi2_data = np.zeros((row, column))
        list1 = dataframe[i].unique()
        list2 = dataframe[variable_y].unique()
        for j in range(len(list1)):
            for k in range(len(list2)):
                chi2_data[j, k] = len(dataframe[(dataframe[i] == list1[j])
                                                & (dataframe[variable_y] == list2[k])])
                count += len(dataframe[(dataframe[i] == list1[j])
                                       & (dataframe[variable_y] == list2[k])])
        res = stats.chi2_contingency(np.array(chi2_data))
        print('chi2Test between', i, 'and', variable_y, ':\n',
              'p-value is :', res[1], ':\n',
              'free degree is :', res[2], ':\n',
              'there are totally', count, 'samples')
        if show:
            print('chi2Test metrix between', i, 'and', variable_y, ':\n', chi2_data)


# Mann-Whitney U test
def wilcox(dataframe, variables, groupby, show=''):
    for j in groupby:
        for i in variables:
            group1 = dataframe[(dataframe[j] == 1) & (dataframe[i].notnull())][i]
            group2 = dataframe[(dataframe[j] == 0) & (dataframe[i].notnull())][i]
            res = stats.mannwhitneyu(group1, group2)
            print(i, ':', res)
            if (show != '') & (i == show):
                fig = plt.figure(figsize=(5, 5), dpi=300)
                ax1 = fig.add_subplot(111)
                ax1.hist([group1, group2], bins=50)
                plt.show()



def meanFill(dataframe, variables_list, show=False):
    for i in variables_list:
        dataframe[i].fillna(dataframe[i].mean(),inplace=True)