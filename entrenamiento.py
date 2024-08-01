
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import BaggingClassifier, RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV


# Ruta del archivo CSV en Google Drive
archivo_csv = '/Users/chris/Documents/Antipishing/data.xlsx'

# Leer el archivo CSV con pandas
data = pd.read_excel(archivo_csv)
data2 = pd.read_excel(archivo_csv)

correlaciones=data2.corr()["tipoUrl"]
correlaciones

data2.drop(columns=['URL_slash'], inplace=True)
data2.drop(columns=['Domain_https'], inplace=True)
data2.drop(columns=['IP_Address'], inplace=True)
data2.drop(columns=['Submit_email'], inplace=True)
data2.drop(columns=['SFH'], inplace=True)

data.drop(columns=['Domain_https'], inplace=True)
data.drop(columns=['IP_Address'], inplace=True)

# Extracción de características con PCA
from sklearn.decomposition import PCA

# Dividir en características (X) y etiqueta (y)
X = data.drop('tipoUrl', axis=1)
y = data['tipoUrl']

k=5
pca = PCA(n_components=k)
fit = pca.fit(X)
X_transform = pca.transform(X)
C = pca.components_
print(f'Explained Variance: {fit.explained_variance_ratio_}')
print ('Componentes:\n' ,C)
# Convertimos a dataframe
data_pca = pd.DataFrame(X_transform, columns=['PC1', 'PC2', 'РС3', 'РС4','PC5'])
data_pca['tipoUrl'] = y.values


# Separar características y etiquetas
X_data = data.iloc[:, :-1]
Y_data = data.iloc[:, -1]
X_data2 = data2.iloc[:, :-1]
Y_data2 = data2.iloc[:, -1]
X_data_pca = data_pca.iloc[:, :-1]
Y_data_pca = data_pca.iloc[:, -1]

# Dividir los conjuntos de datos en entrenamiento y validación
X_train_data, X_test_data, Y_train_data, Y_test_data = train_test_split(X_data, Y_data, test_size=0.20, random_state=7)
X_train_data2, X_test_data2, Y_train_data2, Y_test_data2 = train_test_split(X_data2, Y_data2, test_size=0.20, random_state=7)
X_train_data_pca, X_test_data_pca, Y_train_data_pca, Y_test_data_pca = train_test_split(X_data_pca, Y_data_pca, test_size=0.20, random_state=7)

# Crear la tabla con las dimensiones
tabla = pd.DataFrame({
    '': ['Data Entrenamiento', 'Data Validación'],
    'Data_orig': [(X_train_data.shape[0], X_train_data.shape[1]), (X_test_data.shape[0], X_test_data.shape[1])],
    'Data_Import': [(X_train_data2.shape[0], X_train_data2.shape[1]), (X_test_data2.shape[0], X_test_data2.shape[1])],
    'Data_PCA': [(X_train_data_pca.shape[0], X_train_data_pca.shape[1]), (X_test_data_pca.shape[0], X_test_data_pca.shape[1])]
})

# Mostrar la tabla
print(tabla)


# Normalizar los datos
scaler = StandardScaler()
X_data = scaler.fit_transform(X_data)
X_data2 = scaler.fit_transform(X_data2)
X_data_pca = scaler.fit_transform(X_data_pca)

# Definir los modelos
modelos = []
modelos.append(('KNN', KNeighborsClassifier()))
modelos.append(('LDA', LinearDiscriminantAnalysis()))
modelos.append(('RL', LogisticRegression(max_iter=1000)))  # Incrementar max_iter
modelos.append(('NB', GaussianNB()))
modelos.append(('BDT', BaggingClassifier(estimator=DecisionTreeClassifier(), n_estimators=100, random_state=42)))
modelos.append(('CART', DecisionTreeClassifier()))
modelos.append(('RF', RandomForestClassifier()))
modelos.append(('ET', ExtraTreesClassifier()))
modelos.append(('GB', GradientBoostingClassifier()))
modelos.append(('SVM', SVC()))

# Evaluar modelos
def evaluar_modelos(X, Y, modelos):
    resultados = []
    nombres = []
    for nombre, modelo in modelos:
        kfold = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_results = cross_val_score(modelo, X, Y, cv=kfold, scoring='accuracy')
        resultados.append(cv_results)
        nombres.append(nombre)
        print(f'{nombre}: {cv_results.mean():.6f} ({cv_results.std():.6f})')
    return resultados, nombres

# Evaluar en los tres conjuntos de datos
print("Evaluación en datos originales:")
resultados_data, nombres_data = evaluar_modelos(X_data, Y_data, modelos)

print("\nEvaluación en datos con importancia:")
resultados_data2, nombres_data2 = evaluar_modelos(X_data2, Y_data2, modelos)

print("\nEvaluación en datos con PCA:")
resultados_data_pca, nombres_data_pca = evaluar_modelos(X_data_pca, Y_data_pca, modelos)

# Almacenar resultados en DataFrame
resultados_df = pd.DataFrame({
    'Algorithm': nombres_data,
    'Accuracy data Original': [result.mean() for result in resultados_data],
    'Accuracy data Import': [result.mean() for result in resultados_data2],
    'Accuracy Data PCA': [result.mean() for result in resultados_data_pca]
})

print("\nRendimiento promedio de los algoritmos base")
print(resultados_df)

# Ordenar resultados de forma descendente
resultados_df_sorted_original = resultados_df.sort_values(by='Accuracy data Original', ascending=False)
resultados_df_sorted_import = resultados_df.sort_values(by='Accuracy data Import', ascending=False)
resultados_df_sorted_pca = resultados_df.sort_values(by='Accuracy Data PCA', ascending=False)

print("\nRendimiento promedio de los algoritmos base (ordenado por Accuracy data Original)")
print(resultados_df_sorted_original)

print("\nRendimiento promedio de los algoritmos base (ordenado por Accuracy data Import)")
print(resultados_df_sorted_import)

print("\nRendimiento promedio de los algoritmos base (ordenado por Accuracy Data PCA)")
print(resultados_df_sorted_pca)


# Definir los modelos
modelos = []
modelos.append(('GB', GradientBoostingClassifier()))
modelos.append(('SVM', SVC()))
modelos.append(('RF', RandomForestClassifier()))
modelos.append(('ET', ExtraTreesClassifier()))


# Evaluar modelos
def evaluar_modelos(X, Y, modelos):
    resultados = []
    nombres = []
    for nombre, modelo in modelos:
        kfold = StratifiedKFold(n_splits=25, shuffle=True, random_state=42)
        cv_results = cross_val_score(modelo, X, Y, cv=kfold, scoring='accuracy')
        resultados.append(cv_results)
        nombres.append(nombre)
        print(f'{nombre}: {cv_results.mean():.6f} ({cv_results.std():.6f})')
    return resultados, nombres

# Evaluar en los tres conjuntos de datos
print("Evaluación en datos originales:")
resultados_data, nombres_data = evaluar_modelos(X_data, Y_data, modelos)

print("\nEvaluación en datos con importancia:")
resultados_data2, nombres_data2 = evaluar_modelos(X_data2, Y_data2, modelos)

print("\nEvaluación en datos con PCA:")
resultados_data_pca, nombres_data_pca = evaluar_modelos(X_data_pca, Y_data_pca, modelos)

# Almacenar resultados en DataFrame
resultados_df = pd.DataFrame({
    'Algorithm': nombres_data,
    'Accuracy data Original': [result.mean() for result in resultados_data],
    'Accuracy data Import': [result.mean() for result in resultados_data2],
    'Accuracy Data PCA': [result.mean() for result in resultados_data_pca],
    'Desv data original':[result.std() for result in resultados_data],
    'Desv data Import':[result.std() for result in resultados_data2],
    'Desv Data PCA':[result.std() for result in resultados_data_pca]})

print("\nRendimiento promedio de los algoritmos base")
print(resultados_df)

#Grid Search in Random Forest
n=np.array([50,100,250,500,750])
c=np.array(['gini', 'entropy'])
m=np.array([2,3])
max_features=np.array([2, 3, 4, 5, 6, 7, 8, 9, 10])
b=np.array([True,False])
rs=np.array([7])
param_grid=dict(n_estimators=n, criterion=c, min_samples_split=m, max_features=max_features, bootstrap=b, random_state=rs)
model=RandomForestClassifier()
grid=GridSearchCV(model, param_grid=param_grid, cv=5)
grid.fit(X_train_data, Y_train_data)
print("Random Forest")
print(f"Mejor Accuracy: {grid.best_score_.mean()*100.0:,.2f}%")
print(f"Mejor n_estimators: {grid.best_estimator_.n_estimators}")
print(f"Mejor criterion: {grid.best_estimator_.criterion}")
print(f"Mejor min_ss: {grid.best_estimator_.min_samples_split}")
print(f"Mejor max_features: {grid.best_estimator_.max_features}")
print(f"Mejor bootstrap: {grid.best_estimator_.bootstrap}")

#Grid Search in Extra Trees Classifier
n=np.array([50,100,250,500,750])
c=np.array(['gini', 'entropy'])
m=np.array([2,3])
max_features=np.array([2, 3, 4, 5, 6, 7, 8, 9, 10])
b=np.array([True,False])
rs=np.array([7])
param_grid=dict(n_estimators=n, criterion=c, min_samples_split=m, max_features=max_features, bootstrap=b, random_state=rs)
model=ExtraTreesClassifier()
grid=GridSearchCV(model, param_grid=param_grid, cv=5)
grid.fit(X_train_data, Y_train_data)
print("Extra Trees Classifier")
print(f"Mejor Accuracy: {grid.best_score_.mean()*100.0:,.2f}%")
print(f"Mejor n_estimators: {grid.best_estimator_.n_estimators}")
print(f"Mejor criterion: {grid.best_estimator_.criterion}")
print(f"Mejor min_ss: {grid.best_estimator_.min_samples_split}")
print(f"Mejor max_features: {grid.best_estimator_.max_features}")
print(f"Mejor bootstrap: {grid.best_estimator_.bootstrap}")

# Definir la cuadrícula de parámetros para Grid Search
C = np.array([0.1, 1, 10, 100])
kernel = np.array(['linear', 'poly', 'rbf', 'sigmoid'])
degree = np.array([2, 3, 4])
gamma = np.array(['scale', 'auto'])
param_grid = dict(C=C, kernel=kernel, degree=degree, gamma=gamma)

# Inicializar el Support Vector Classifier
model = SVC()

# Inicializar Grid Search con validación cruzada de 5 pliegues
grid = GridSearchCV(model, param_grid=param_grid, cv=5)

# Suponiendo que X_train_data y Y_train_data ya están definidos
grid.fit(X_train_data, Y_train_data)


# Imprimir mejor puntuación y mejores parámetros
print("SVC")
print(f"Mejor Accuracy: {grid.best_score_*100.0:,.2f}%")
print(f"Mejor C: {grid.best_estimator_.C}")
print(f"Mejor kernel: {grid.best_estimator_.kernel}")
print(f"Mejor degree: {grid.best_estimator_.degree}")
print(f"Mejor gamma: {grid.best_estimator_.gamma}")

# Define parameter grid for Grid Search
n = np.array([50, 100, 250, 500, 750])
m = np.array([2, 3])
rs = np.array([7])
param_grid = dict(n_estimators=n, min_samples_split=m)

# Initialize the Gradient Boosting Classifier
model = GradientBoostingClassifier(random_state=7)

# Initialize Grid Search with 5-fold cross-validation
grid = GridSearchCV(model, param_grid=param_grid, cv=5)

# Assuming X_train_data and Y_train_data are already defined
grid.fit(X_train_data, Y_train_data)

# Print best score and best parameters
print("Gradient Boosting Classifier")
print(f"Mejor Accuracy: {grid.best_score_*100.0:,.2f}%")
print(f"Mejor n_estimators: {grid.best_estimator_.n_estimators}")
print(f"Mejor min_samples_split: {grid.best_estimator_.min_samples_split}")
