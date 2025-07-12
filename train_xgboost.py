# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, RandomizedSearchCV, RepeatedStratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, classification_report, confusion_matrix
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
import seaborn as sns

import warnings
warnings.filterwarnings('ignore')

def load_and_preprocess_data(file_path):
    print("📂 Loading dataset...")
    train_df = pd.read_csv(file_path)
    print(f"Dataset shape: {train_df.shape}")
    
    print("🔧 Handling missing values...")
    train_df["rx_kbps"].fillna(train_df["rx_kbps"].mean(), inplace=True)
    train_df["tot_kbps"].fillna(train_df["tot_kbps"].mean(), inplace=True)
    
    # Remove unnecessary columns
    remove_cols = ["dt", "tx_kbps", "pktperflow", "pktrate"]
    existing_remove_cols = [col for col in remove_cols if col in train_df.columns]
    if existing_remove_cols:
        train_df.drop(existing_remove_cols, axis=1, inplace=True)
        print(f"Removed columns: {existing_remove_cols}")
    
    # Apply Label Encoding to categorical columns and save encoders
    print("🏷️ Applying Label Encoding...")
    label_encoders = {}
    
    # Identify categorical columns
    categorical_cols = ['src', 'dst', 'Protocol', 'Pairflow', 'port_no']
    
    for col in categorical_cols:
        if col in train_df.columns:
            le = LabelEncoder()
            train_df[col] = le.fit_transform(train_df[col])
            label_encoders[col] = le
            print(f"Encoded {col}: {dict(zip(le.classes_, range(len(le.classes_))))}")
    
    print(f"Final dataset shape: {train_df.shape}")
    print(f"Columns: {list(train_df.columns)}")
    return train_df, label_encoders

def prepare_features_target(df):
    """
    Separate features and target variable
    """
    print("🎯 Preparing features and target...")
    X = df.drop(columns='label')
    y = df['label']
    
    print("📏 Standardizing features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"Features shape: {X_scaled.shape}")
    print(f"Target distribution:\n{y.value_counts()}")
    
    return X_scaled, y, scaler

def train_xgboost_model(X_train, y_train):
    """
    Train XGBoost model with RandomizedSearchCV (exact same as notebook)
    """
    print("🚀 Training XGBoost model with hyperparameter tuning...")
    
    xgb_params = {
        'n_estimators': [100, 200, 300],
        'learning_rate': [0.1],
        'max_depth': [None, 5, 10, 20, 30],
        'min_child_weight': [1],
        'gamma': [0, 0.5, 1, 1.5, 2, 5],
        'subsample': [0.6, 0.8, 1.0],
        'colsample_bytree': [0.6, 0.8, 1.0],
        'colsample_bylevel': [1],
        'reg_alpha': [1],
        'reg_lambda': [0],
    }
    
    # Cross-validation setup 
    skf = RepeatedStratifiedKFold(n_splits=3)
    
    # RandomizedSearchCV 
    xgb = RandomizedSearchCV(
        estimator=XGBClassifier(random_state=42),
        param_distributions=xgb_params, 
        cv=skf, 
        n_iter=5, 
        n_jobs=4, 
        verbose=0,
        random_state=42
    )
    
    # Fit model
    xgb_model = xgb.fit(X_train, y_train)
    
    print(f"✅ Best parameters: {xgb_model.best_params_}")
    print(f"✅ Best cross-validation score: {xgb_model.best_score_:.4f}")
    
    return xgb_model

def evaluate_model(model, X_train, X_test, y_train, y_test):
    """
    Evaluate the trained model
    """
    print("📊 Evaluating model...")
    
    # Predictions
    train_pred = model.predict(X_train)
    test_pred = model.predict(X_test)
    
    # Calculate metrics
    train_accuracy = accuracy_score(y_train, train_pred)
    test_accuracy = accuracy_score(y_test, test_pred)
    train_precision = precision_score(y_train, train_pred)
    test_precision = precision_score(y_test, test_pred)
    train_recall = recall_score(y_train, train_pred)
    test_recall = recall_score(y_test, test_pred)
    
    # Print results
    print(f"Training Accuracy: {train_accuracy * 100:.2f}%")
    print(f"Test Accuracy: {test_accuracy * 100:.2f}%")
    print(f"Training Precision: {train_precision * 100:.2f}%")
    print(f"Test Precision: {test_precision * 100:.2f}%")
    print(f"Training Recall: {train_recall * 100:.2f}%")
    print(f"Test Recall: {test_recall * 100:.2f}%")
    
    # Classification report
    print("\n📋 Classification Report:")
    print(classification_report(y_test, test_pred))
    
    return {
        'train_accuracy': train_accuracy,
        'test_accuracy': test_accuracy,
        'train_precision': train_precision,
        'test_precision': test_precision,
        'train_recall': train_recall,
        'test_recall': test_recall
    }

def save_model_pickle(model, scaler, feature_columns, metrics, label_encoders, filename='xgboost.pkl'):
    """
    Save the trained model and preprocessing components to pickle file
    """
    print(f"💾 Saving model to {filename}...")
    
    model_package = {
        'model': model,
        'scaler': scaler,
        'feature_columns': feature_columns,
        'metrics': metrics,
        'label_encoders': label_encoders,
        'model_type': 'XGBoost',
        'description': 'DDoS SDN Detection Model'
    }
    
    with open(filename, 'wb') as f:
        pickle.dump(model_package, f)
    
    print(f"✅ Model saved successfully to {filename}")
    return filename


def plot_confusion_matrix(y_test, y_pred, save_path='confusion_matrix.png'):
    """
    Vẽ biểu đồ confusion matrix
    """
    print("📊 Plotting confusion matrix...")
    
    # Tạo confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    
    # Thiết lập figure
    plt.figure(figsize=(8, 6))
    
    # Vẽ heatmap
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                cbar_kws={'label': 'Count'},
                xticklabels=['Benign', 'Malicious'], 
                yticklabels=['Benign', 'Malicious'])
    
    # Thiết lập labels và title
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.title('Confusion Matrix - XGBoost Model', fontsize=14, fontweight='bold')
    
    # Điều chỉnh layout
    plt.tight_layout()
    
    # Hiển thị và lưu
    plt.savefig(save_path)
    plt.show()

    plt.close()
    
    print(f"✅ Confusion matrix saved to {save_path}")

def plot_classification_report_heatmap(y_test, y_pred, save_path='classification_report_heatmap.png'):
    """
    Vẽ biểu đồ classification report dưới dạng heatmap
    """
    print("📊 Plotting classification report heatmap...")
    
    # Tạo classification report
    report_dict = classification_report(y_test, y_pred, output_dict=True)
    
    # Chuyển đổi thành DataFrame
    df = pd.DataFrame(report_dict).transpose().round(3)
    
    # Loại bỏ hàng 'support' và cột 'support' để chỉ giữ precision, recall, f1-score
    df = df.drop('support', axis=1)
    df = df.drop(['accuracy', 'macro avg', 'weighted avg'], axis=0)
    
    # Thiết lập figure
    plt.figure(figsize=(10, 6))
    
    # Vẽ heatmap
    sns.heatmap(df, annot=True, cmap='YlOrRd', fmt=".3f", 
                linewidths=0.5, linecolor='gray',
                cbar_kws={'label': 'Score'})
    
    # Thiết lập labels và title
    plt.title("Classification Report Heatmap", fontsize=14, fontweight='bold')
    plt.ylabel("Classes", fontsize=12)
    plt.xlabel("Metrics", fontsize=12)
    
    # Điều chỉnh layout
    plt.tight_layout()
    
    # Hiển thị và lưu
    
    plt.savefig(save_path)
    plt.show()

    plt.close()
    
    print(f"✅ Classification report heatmap saved to {save_path}")

def plot_metrics_comparison(metrics_dict, save_path='metrics_comparison.png'):
    """
    Vẽ biểu đồ so sánh các metrics giữa training và test
    """
    print("📊 Plotting metrics comparison...")
    
    # Chuẩn bị dữ liệu
    train_metrics = [
        metrics_dict['train_accuracy'],
        metrics_dict['train_precision'], 
        metrics_dict['train_recall']
    ]
    
    test_metrics = [
        metrics_dict['test_accuracy'],
        metrics_dict['test_precision'],
        metrics_dict['test_recall']
    ]
    
    metric_names = ['Accuracy', 'Precision', 'Recall']
    
    # Thiết lập figure
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Vị trí bars
    x = np.arange(len(metric_names))
    width = 0.35
    
    # Vẽ bars
    bars1 = ax.bar(x - width/2, train_metrics, width, label='Training', 
                   color='skyblue', alpha=0.8)
    bars2 = ax.bar(x + width/2, test_metrics, width, label='Test', 
                   color='lightcoral', alpha=0.8)
    
    # Thêm giá trị trên bars
    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f'{height:.3f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f'{height:.3f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom', fontsize=10)
    
    # Thiết lập labels và title
    ax.set_xlabel('Metrics', fontsize=12)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Performance Comparison: Training vs Test', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(metric_names)
    ax.legend()
    ax.set_ylim(0, 1.1)
    
    # Thêm grid
    ax.grid(True, alpha=0.3)
    
    # Điều chỉnh layout
    plt.tight_layout()
    
    # Hiển thị và lưu
    
    plt.savefig(save_path)
    plt.show()
    plt.close()
    
    print(f"✅ Metrics comparison saved to {save_path}")

def plot_class_distribution(y_train, y_test, save_path='class_distribution.png'):
    """
    Vẽ biểu đồ phân phối các class trong training và test set
    """
    print("📊 Plotting class distribution...")
    
    # Đếm số lượng mỗi class
    train_counts = pd.Series(y_train).value_counts().sort_index()
    test_counts = pd.Series(y_test).value_counts().sort_index()
    
    # Thiết lập figure
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Training set distribution
    colors = ['lightblue', 'lightcoral']
    labels = ['Benign', 'Malicious']
    
    ax1.pie(train_counts.values, labels=labels, autopct='%1.1f%%', 
            colors=colors, startangle=90)
    ax1.set_title('Training Set Distribution', fontsize=12, fontweight='bold')
    
    # Test set distribution
    ax2.pie(test_counts.values, labels=labels, autopct='%1.1f%%', 
            colors=colors, startangle=90)
    ax2.set_title('Test Set Distribution', fontsize=12, fontweight='bold')
    
    # Điều chỉnh layout
    plt.tight_layout()
    
    # Hiển thị và lưu
    plt.savefig(save_path)
    plt.show()
    plt.close()
    
    print(f"✅ Class distribution saved to {save_path}")

def plot_all_charts(model, X_test, y_test, y_train, metrics_dict):
    """
    Vẽ tất cả biểu đồ
    """
    print("🎨 Generating all visualization charts...")
    
    # Dự đoán
    y_pred = model.predict(X_test)
    
    # Vẽ từng biểu đồ
    plot_confusion_matrix(y_test, y_pred)
    plot_classification_report_heatmap(y_test, y_pred)
    plot_metrics_comparison(metrics_dict)
    plot_class_distribution(y_train, y_test)
    
    print("✅ All charts generated successfully!")


def main():
    """
    Main training pipeline
    """
    print("🎯 Starting XGBoost Training Pipeline for DDoS SDN Detection")
    print("=" * 60)
    
    # Load and preprocess data
    df, label_encoders = load_and_preprocess_data('dataset_sdn.csv')
    
    # Prepare features and target
    X, y, scaler = prepare_features_target(df)
    
    # Get feature column names before scaling
    feature_columns = [col for col in df.columns if col != 'label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42
    )
    print(f"📊 Train set: {X_train.shape}, Test set: {X_test.shape}")
    
    # Train model
    model = train_xgboost_model(X_train, y_train)
    
    # Evaluate model
    metrics = evaluate_model(model, X_train, X_test, y_train, y_test)
    
    # Save model to pickle
    save_model_pickle(model, scaler, feature_columns, metrics, label_encoders)
    
    # Generate all visualization charts
    plot_all_charts(model, X_test, y_test, y_train, metrics)

    print("\n🎉 Training completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()