using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Schema;
using Polly;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.UI.WebControls;

/// <summary>
///     This Library requires .NET 4 or above
///     It performs some basic functions to make things easier
///     Uses Polly to do perform resilient SQL operations
///     
/// </summary>
public static class EnumExtensions
{
    public static TAttribute GetAttribute<TAttribute>(this Enum value)
        where TAttribute : Attribute
    {
        var type = value.GetType();
        var name = Enum.GetName(type, value);
        return type.GetField(name) // I prefer to get attributes this way
            .GetCustomAttributes(false)
            .OfType<TAttribute>()
            .SingleOrDefault();
    }
}

public static class DateTimeExtensions
{
    public static DateTime StartOfWeek(this DateTime dt, DayOfWeek startOfWeek)
    {
        var diff = (7 + (dt.DayOfWeek - startOfWeek)) % 7;
        return dt.AddDays(-1 * diff).Date;
    }
}

public static class StringExtensions
{
    public static bool Contains(this string stringToSearch, string stringToLookFor, StringComparison comparisonMethod)
    {
        if (stringToLookFor == null)
            throw new ArgumentNullException("Substring", "Substring cannot be null.");
        if (!Enum.IsDefined(typeof(StringComparison), comparisonMethod))
            throw new ArgumentException("Comp is not a member of StringComparison", "Comp");
        return stringToSearch.IndexOf(stringToLookFor, comparisonMethod) >= 0;
    }
}

public static class SqlExtensions
{
    // See https://docs.microsoft.com/azure/active-directory/managed-identities-azure-resources/services-support-managed-identities#azure-sql
    private static readonly string[] AzureSqlScopes = { "https://database.windows.net//.default" };

    private static readonly TokenCredential Credential =
        new ChainedTokenCredential(new ManagedIdentityCredential(), new EnvironmentCredential());

    public static void OpenSqlConnection(this SqlConnection connection)
    {
        if (DoesConnectionNeedAccessToken(connection))
        {
            var tokenRequestContext = new TokenRequestContext(AzureSqlScopes);
            var accessToken = Credential.GetToken(tokenRequestContext, default);
            connection.AccessToken = accessToken.Token;
        }

        connection.Open();
    }

    public static async Task OpenSqlConnectionAsync(this SqlConnection connection, CancellationToken cancellationToken)
    {
        if (DoesConnectionNeedAccessToken(connection))
        {
            var tokenRequestContext = new TokenRequestContext(AzureSqlScopes);
            var accessToken = await Credential.GetTokenAsync(tokenRequestContext, default);
            connection.AccessToken = accessToken.Token;
        }

        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
    }

    private static bool DoesConnectionNeedAccessToken(IDbConnection connection)
    {
        //
        // Only try to get a token from AAD if
        //  - We connect to an Azure SQL instance; and
        //  - The connection doesn't specify a username.
        //
        var connectionStringBuilder = new SqlConnectionStringBuilder(connection.ConnectionString);
        return connectionStringBuilder.DataSource.Contains("database.windows.net",
            StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(connectionStringBuilder.UserID);
    }
}

public class SqlResult
{
    public SqlResult()
    {
        ErrorMessage = string.Empty;
        IsCriticalError = false;
    }

    public object Result { get; set; }
    public string ErrorMessage { get; set; }
    public bool IsCriticalError { get; set; }
}

public class CommonLibrary
{
    public const int DatabaseRetries = 4; // number of retries for database connection/read/write
    public const int DatabaseRetryInterval = 5; // number of seconds before each retry

    public const int PrecisionMoney = 2; // Money type precision

    public const int StandardBluetoothAddressLength = 12; // Standard Bluetooth Address Length without any symbol

    public static List<int> DatabaseCancellableErrors = new(new[] { -1, 233, 18456 });

    public static string DeveloperEmailAddress = "xxx@xxx.com"; // This address is used whenever the an Email is needed to be sent out by from code.

    public static string UsPacificTimeZoneLookupName = "Pacific Standard Time";
    public static string UsPacificTimeZoneDateOnlyFormat = "yyyy-MM-dd";
    public static string UsPacificTimeZoneDateTimeFormat = "yyyy-MM-dd HH:mm:ss";
    public static bool AllowDebugMessage { get; set; }
    public static bool AllowLogMessage { get; set; }
    public static ILogger ApplicationLog { get; set; }

    public static DateTime GetSqlResultDate(SqlResult sqlResult)
    {
        return CleanDate(sqlResult.Result);
    }

    public static decimal GetSqlResultDecimal(SqlResult sqlResult)
    {
        return CleanDecimal(sqlResult.Result);
    }

    public static bool GetSqlResultBool(SqlResult sqlResult)
    {
        return CleanBit(sqlResult.Result);
    }

    public static string GetSqlResultString(SqlResult sqlResult)
    {
        return CleanText(sqlResult.Result);
    }

    public static int GetSqlResultInt(SqlResult sqlResult)
    {
        // Use with SqlSelectOneIntegerAsync and SqlCrudAsync
        return CleanInt(sqlResult.Result);
    }

    public static DataSet GetSqlResultDataSet(SqlResult sqlResult)
    {
        // Use with SqlSelectDataSetAsync
        return sqlResult.Result as DataSet;
    }

    public static DataRow GetSqlResultDataRow(SqlResult sqlResult)
    {
        return sqlResult.Result as DataRow;
    }

    public static bool IsSqlResultGood(SqlResult sqlResult, bool isRowsAffectedOrReturnedConsidered)
    {
        if (sqlResult.IsCriticalError) return false;
        if (sqlResult == null) return false;
        try
        {
            switch (sqlResult.Result)
            {
                // For CRUD and SELECT INT operations
                case int when isRowsAffectedOrReturnedConsidered:
                    {
                        var tempResult = CleanInt(sqlResult);
                        return
                            tempResult >
                            0; // for CRUD and SELECT INT operations, return the number of rows affected OR the INT single result
                    }
                case int:
                    return true; // always return true if we do not consider number of rows affected
                // For SELECT DataSet operations
                case DataSet set when isRowsAffectedOrReturnedConsidered:
                    return !IsDataSetEmpty(set); // For SELECT DataSet, make sure rows are returned
                case DataSet:
                    return true; // always return true if we do not consider number of rows returned
            }
        }
        catch
        {
            // ignored
        }

        return false; // unknown other types we return false!
    }

    public static bool IsSqlReturnGood(int input)
    {
        return input >= 0;
    }

    public static int SqlSelectOneInteger(string connectionString, string sql, List<SqlParameter> sqlParameters,
        out string databaseErrorMessage)
    {
        return CleanInt(SqlSelectOneInteger(connectionString, CommandType.Text, sql, sqlParameters,
            out databaseErrorMessage));
    }

    public static async Task<SqlResult> SqlSelectOneIntegerAsync(string connectionString, string sql,
        List<SqlParameter> sqlParameters)
    {
        return await SqlSelectOneIntegerAsync(connectionString, CommandType.Text, sql, sqlParameters);
    }

    public static object SqlSelectOneInteger(string connectionString, CommandType ctCommandType, string sql,
        List<SqlParameter> sqlParameters, out string databaseErrorMessage)
    {
        ShowInfoAndError("SqlSelectOneInteger", $"Start {DateTime.Now:G}");
        object objReturnValue = null;
        databaseErrorMessage = string.Empty;
        using (var sqlConnection = new SqlConnection(connectionString))
        {
            using var sqlCommand = new SqlCommand(sql, sqlConnection);
            sqlCommand.CommandType = ctCommandType;
            if (sqlParameters != null) sqlCommand.Parameters.AddRange(sqlParameters.ToArray());
            for (var tries = 1; tries <= DatabaseRetries; tries++)
            {
                if (tries > 1)
                {
                    ShowInfoAndError("SqlSelectOneInteger",
                        $"Transient error encountered during connection. Will begin attempt number {tries} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {databaseErrorMessage}");
                    Thread.Sleep(CleanInt(DatabaseRetryInterval * 1000 * Math.Pow(2, tries - 1)));
                }
                else
                {
                    ShowInfoAndError("SqlSelectOneInteger",
                        $"Initial connection. Number {tries} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {databaseErrorMessage}");
                }
                try
                {
                    if (sqlConnection.State != ConnectionState.Open) sqlConnection.OpenSqlConnection();
                    objReturnValue = sqlCommand.ExecuteScalar();
                    databaseErrorMessage = string.Empty;
                    sqlCommand.Parameters.Clear();
                    break;
                }
                catch (SqlException ex)
                {
                    databaseErrorMessage = GetSqlException(sql, ex);
                }
                catch (Exception ex)
                {
                    databaseErrorMessage = GetStandardException(ex);
                }
            }
            sqlCommand.Parameters.Clear();
        }

        ShowInfoAndError("SqlSelectOneInteger",
            $"Return. Error Message: {databaseErrorMessage}. Result: {CleanInt(objReturnValue)}.");
        return objReturnValue;
    }

    public static async Task<SqlResult> SqlSelectOneIntegerAsync(string connectionString, CommandType ctCommandType,
        string sql, List<SqlParameter> sqlParameters)
    {
        ShowInfoAndError("SqlSelectOneIntegerAsync", $"Start {DateTime.Now:G}");
        var sqlResult = new SqlResult { Result = null, ErrorMessage = string.Empty, IsCriticalError = false };
        var retryCount = 1;
        var policy = Policy.Handle<SqlException>().Or<Exception>().WaitAndRetryAsync(
            DatabaseRetries, // Retry DatabaseRetries times
            attempt => TimeSpan.FromMilliseconds(DatabaseRetryInterval * 1000 *
                                                 Math.Pow(2, attempt - 1)), // Exponential back-off
            (exception, attempt, contextForCancel) =>
            {
                ShowPollySql("SqlSelectOneIntegerAsync", attempt, retryCount, DatabaseRetries, sql, exception);
                sqlResult.ErrorMessage += GetScreenOutputText(GetPollyException(sql, exception));
                if (IsExceptionCancellable(exception))
                {
                    var cancellationTokenSourceForCancel =
                        contextForCancel["CancellationTokenSource"] as CancellationTokenSource;
                    cancellationTokenSourceForCancel?.Cancel();
                    ShowInfoAndError("SqlSelectOneIntegerAsync", "Retry Cancelled");
                    sqlResult.IsCriticalError = true;
                }
                retryCount++;
            }
        );
        var cancellationTokenSourceMain = new CancellationTokenSource();
        var contextMain = new Context("RetryContext") { { "CancellationTokenSource", cancellationTokenSourceMain } };
        using (var sqlConnection = new SqlConnection(connectionString))
        {
            using var sqlCommand = new SqlCommand(sql, sqlConnection);
            sqlCommand.CommandType = ctCommandType;
            if (sqlParameters != null) sqlCommand.Parameters.AddRange(sqlParameters.ToArray());
            try
            {
                sqlResult.Result = CleanInt(await policy.ExecuteAsync(async (_, token) =>
                {
                    if (sqlConnection.State == ConnectionState.Open)
                        return await sqlCommand.ExecuteScalarAsync(token).ConfigureAwait(false);
                    ShowInfoAndError("SqlSelectOneIntegerAsync",
                        retryCount > 1
                            ? $"Transient error encountered during connection. Will begin attempt number {retryCount} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {sqlResult.ErrorMessage}"
                            : $"Initial connection. Number {retryCount} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {sqlResult.ErrorMessage}");
                    await sqlConnection.OpenSqlConnectionAsync(token);

                    return await sqlCommand.ExecuteScalarAsync(token).ConfigureAwait(false);
                }, contextMain, cancellationTokenSourceMain.Token));
                sqlResult.ErrorMessage = string.Empty;
                sqlResult.IsCriticalError = false;
                sqlCommand.Parameters.Clear();
            }
            catch (SqlException ex)
            {
                sqlResult.ErrorMessage =
                    GetScreenOutputText(
                        $"SqlSelectOneIntegerAsync Final Error. {GetSqlException(sql, ex)} {Environment.NewLine}") +
                    sqlResult.ErrorMessage;
                sqlResult.IsCriticalError = true;
            }
            catch (Exception ex)
            {
                sqlResult.ErrorMessage =
                    GetScreenOutputText(
                        $"SqlSelectOneIntegerAsync Final Error. {GetStandardException(ex)} {Environment.NewLine}") +
                    sqlResult.ErrorMessage;
                sqlResult.IsCriticalError = true;
            }
        }

        ShowInfoAndError("SqlSelectOneIntegerAsync",
            $"Return with IsCriticalError: {sqlResult.IsCriticalError}. Error Message: {sqlResult.ErrorMessage}. Result: {CleanInt(sqlResult.Result)}.");
        return sqlResult;
    }

    public static DataSet SqlSelectDataSet(string connectionString, string sql, List<SqlParameter> sqlParameters,
        out string databaseErrorMessage)
    {
        return SqlSelectDataSet(connectionString, sql, CommandType.Text, sqlParameters, out databaseErrorMessage);
    }

    public static async Task<SqlResult> SqlSelectDataSetAsync(string connectionString, string sql,
        List<SqlParameter> sqlParameters)
    {
        return await SqlSelectDataSetAsync(connectionString, CommandType.Text, sql, sqlParameters);
    }

    public static DataSet SqlSelectDataSet(string connectionString, string sql, CommandType commandType,
        List<SqlParameter> sqlParameters, out string databaseErrorMessage)
    {
        ShowInfoAndError("SqlSelectDataSet", $"Start {DateTime.Now:G}");
        var dataSet = new DataSet();
        databaseErrorMessage = string.Empty;
        using (var sqlConnection = new SqlConnection(connectionString))
        {
            using var sqlCommand = new SqlCommand(sql, sqlConnection);
            sqlCommand.CommandType = commandType;
            if (sqlParameters != null) sqlCommand.Parameters.AddRange(sqlParameters.ToArray());
            for (var tries = 1; tries <= DatabaseRetries; tries++)
            {
                if (tries > 1)
                {
                    ShowInfoAndError("SqlSelectDataSet",
                        $"Transient error encountered during connection. Will begin attempt number {tries} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {databaseErrorMessage}");
                    Thread.Sleep(CleanInt(DatabaseRetryInterval * 1000 * Math.Pow(2, tries - 1)));
                }
                else
                {
                    ShowInfoAndError("SqlSelectDataSet",
                        $"Initial connection. Number {tries} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {databaseErrorMessage}");
                }
                try
                {
                    if (sqlConnection.State != ConnectionState.Open) sqlConnection.OpenSqlConnection();
                    using (var dataReader = sqlCommand.ExecuteReader())
                    {
                        dataSet.Tables.Add("DefaultTable");
                        dataSet.Tables[0].Load(dataReader);
                    }
                    databaseErrorMessage = string.Empty;
                    sqlCommand.Parameters.Clear();
                    break;
                }
                catch (SqlException ex)
                {
                    databaseErrorMessage = GetSqlException(sql, ex);
                    dataSet.Clear();
                }
                catch (Exception ex)
                {
                    databaseErrorMessage = GetStandardException(ex);
                    dataSet.Clear();
                }
            }
            sqlCommand.Parameters.Clear();
        }
        var resultCount = !IsDataSetEmpty(dataSet) ? dataSet.Tables[0].Rows.Count.ToString() : "null";
        ShowInfoAndError("SqlSelectDataSet", $"Return. Error Message: {databaseErrorMessage}. Count: {resultCount}.");
        if (!IsDataSetEmpty(dataSet))
            foreach (DataColumn col in dataSet.Tables[0].Columns)
                col.ReadOnly = false;
        return dataSet;
    }

    public static async Task<SqlResult> SqlSelectDataSetAsync(string connectionString, CommandType ctCommandType,
        string sql, List<SqlParameter> sqlParameters)
    {
        ShowInfoAndError("SqlSelectDataSetAsync", $"Start {DateTime.Now:G}");
        var sqlResult = new SqlResult { Result = null, ErrorMessage = string.Empty, IsCriticalError = false };
        var dataSet = new DataSet();
        var retryCount = 1;
        var policy = Policy.Handle<SqlException>().Or<Exception>()
            .WaitAndRetryAsync(
                DatabaseRetries, // Retry DatabaseRetries times
                attempt => TimeSpan.FromMilliseconds(DatabaseRetryInterval * 1000 *
                                                     Math.Pow(2, attempt - 1)), // Exponential back-off
                (exception, attempt, contextForCancel) =>
                {
                    ShowPollySql("SqlSelectDataSetAsync", attempt, retryCount, DatabaseRetries, sql, exception);
                    sqlResult.ErrorMessage += GetScreenOutputText(GetPollyException(sql, exception));
                    if (IsExceptionCancellable(exception))
                    {
                        var cancellationTokenSourceForCancel =
                            contextForCancel["CancellationTokenSource"] as CancellationTokenSource;
                        cancellationTokenSourceForCancel?.Cancel();
                        ShowInfoAndError("SqlSelectDataSetAsync", "Retry Cancelled");
                        sqlResult.IsCriticalError = true;
                    }
                    retryCount++;
                }
            );
        var cancellationTokenSourceMain = new CancellationTokenSource();
        var contextMain = new Context("RetryContext") { { "CancellationTokenSource", cancellationTokenSourceMain } };
        using (var sqlConnection = new SqlConnection(connectionString))
        {
            using var sqlCommand = new SqlCommand(sql, sqlConnection);
            sqlCommand.CommandType = ctCommandType;
            if (sqlParameters != null) sqlCommand.Parameters.AddRange(sqlParameters.ToArray());
            try
            {
                var dataReader = await policy.ExecuteAsync(async (_, token) =>
                {
                    if (sqlConnection.State != ConnectionState.Open)
                    {
                        ShowInfoAndError("SqlSelectDataSetAsync",
                            retryCount > 1
                                ? $"Transient error encountered during connection. Will begin attempt number {retryCount} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {sqlResult.ErrorMessage}"
                                : $"Initial connection. Number {retryCount} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {sqlResult.ErrorMessage}");
                        await sqlConnection.OpenSqlConnectionAsync(token);
                    }

                    ShowInfoAndError("SqlSelectDataSetAsync",
                        $"Got Database Connection {DateTime.Now:G}");
                    return await sqlCommand.ExecuteReaderAsync(token).ConfigureAwait(false);
                }, contextMain, cancellationTokenSourceMain.Token);
                ShowInfoAndError("SqlSelectDataSetAsync", $"Got DataReaderAsync {DateTime.Now:G}");
                dataSet.Tables.Add("DefaultTable");
                if (dataReader != null)
                {
                    ShowInfoAndError("SqlSelectDataSetAsync",
                        $"Add DataReader to DataSet DefaultTable {DateTime.Now:G}");
                    sqlResult.ErrorMessage = string.Empty;
                    sqlResult.IsCriticalError = false;
                    dataSet.Tables[0].Load(dataReader);
                    if (!IsDataSetEmpty(dataSet))
                        foreach (DataColumn col in dataSet.Tables[0].Columns)
                            col.ReadOnly = false;
                    sqlResult.Result = dataSet;
                    sqlCommand.Parameters.Clear();
                }
            }
            catch (SqlException ex)
            {
                sqlResult.ErrorMessage =
                    GetScreenOutputText(
                        $"SqlSelectDataSetAsync Final Error. {GetSqlException(sql, ex)} {Environment.NewLine}") +
                    sqlResult.ErrorMessage;
                sqlResult.IsCriticalError = true;
            }
            catch (Exception ex)
            {
                sqlResult.ErrorMessage =
                    GetScreenOutputText(
                        $"SqlSelectDataSetAsync Final Error. {GetStandardException(ex)} {Environment.NewLine}") +
                    sqlResult.ErrorMessage;
                sqlResult.IsCriticalError = true;
            }
        }
        dataSet = GetSqlResultDataSet(sqlResult);
        var resultCount = !IsDataSetEmpty(dataSet) ? dataSet.Tables[0].Rows.Count.ToString() : "null";
        ShowInfoAndError("SqlSelectDataSetAsync",
            $"Return with IsCriticalError: {sqlResult.IsCriticalError}. Error Message: {sqlResult.ErrorMessage}. Count: {resultCount}.");
        return sqlResult;
    }

    public static async Task<SqlResult> SqlCrudAsync(string connectionString, CommandType ctCommandType, string sql,
        List<SqlParameter> sqlParameters)
    {
        ShowInfoAndError("SqlCrudAsync", $"Start {DateTime.Now:G}");
        var sqlResult = new SqlResult { Result = null, ErrorMessage = string.Empty, IsCriticalError = false };
        var retryCount = 1;
        var policy = Policy.Handle<SqlException>().Or<Exception>().WaitAndRetryAsync(
            DatabaseRetries, // Retry DatabaseRetries times
            attempt => TimeSpan.FromMilliseconds(DatabaseRetryInterval * 1000 *
                                                 Math.Pow(2, attempt - 1)), // Exponential back-off
            (exception, attempt, contextForCancel) =>
            {
                ShowPollySql("SqlCrudAsync", attempt, retryCount, DatabaseRetries, sql, exception);
                sqlResult.ErrorMessage += GetScreenOutputText(GetPollyException(sql, exception));
                if (IsExceptionCancellable(exception))
                {
                    var cancellationTokenSourceForCancel =
                        contextForCancel["CancellationTokenSource"] as CancellationTokenSource;
                    cancellationTokenSourceForCancel?.Cancel();
                    ShowInfoAndError("SqlCrudAsync", "Retry Cancelled");
                    sqlResult.IsCriticalError = true;
                }
                retryCount++;
            }
        );
        var cancellationTokenSourceMain = new CancellationTokenSource();
        var contextMain = new Context("RetryContext") { { "CancellationTokenSource", cancellationTokenSourceMain } };
        using (var sqlConnection = new SqlConnection(connectionString))
        {
            using var sqlCommand = new SqlCommand(sql, sqlConnection);
            sqlCommand.CommandType = ctCommandType;
            if (sqlParameters != null) sqlCommand.Parameters.AddRange(sqlParameters.ToArray());
            try
            {
                sqlResult.Result = CleanInt(await policy.ExecuteAsync(async (_, token) =>
                {
                    if (sqlConnection.State == ConnectionState.Open)
                        return await sqlCommand.ExecuteNonQueryAsync(token).ConfigureAwait(false);
                    ShowInfoAndError("SqlCrudAsync",
                        retryCount > 1
                            ? $"Transient error encountered during connection. Will begin attempt number {retryCount} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {sqlResult.ErrorMessage}"
                            : $"Initial connection. Number {retryCount} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {sqlResult.ErrorMessage}");
                    await sqlConnection.OpenSqlConnectionAsync(token);

                    return await sqlCommand.ExecuteNonQueryAsync(token).ConfigureAwait(false);
                }, contextMain, cancellationTokenSourceMain.Token));
                sqlResult.ErrorMessage = string.Empty;
                sqlResult.IsCriticalError = false;
                sqlCommand.Parameters.Clear();
            }
            catch (SqlException ex)
            {
                sqlResult.ErrorMessage =
                    GetScreenOutputText(
                        $"SqlCrudAsync Final Error. {GetSqlException(sql, ex)} {Environment.NewLine}") +
                    sqlResult.ErrorMessage;
                sqlResult.IsCriticalError = true;
            }
            catch (Exception ex)
            {
                sqlResult.ErrorMessage =
                    GetScreenOutputText(
                        $"SqlCrudAsync Final Error. {GetStandardException(ex)} {Environment.NewLine}") +
                    sqlResult.ErrorMessage;
                sqlResult.IsCriticalError = true;
            }
        }
        ShowInfoAndError("SqlCrudAsync",
            $"Return with IsCriticalError: {sqlResult.IsCriticalError}. Error Message: {sqlResult.ErrorMessage}. Result: {CleanInt(sqlResult.Result)}.");
        return sqlResult;
    }

    public static int SqlCrud(string connectionString, string sql, List<SqlParameter> sqlParameters,
        out string databaseErrorMessage)
    {
        return SqlCrud(connectionString, CommandType.Text, sql, sqlParameters, out databaseErrorMessage);
    }

    public static async Task<SqlResult> SqlCrudAsync(string connectionString, string sql,
        List<SqlParameter> sqlParameters)
    {
        return await SqlCrudAsync(connectionString, CommandType.Text, sql, sqlParameters);
    }

    public static int SqlCrud(string connectionString, CommandType ctCommandType, string sql,
        List<SqlParameter> sqlParameters, out string databaseErrorMessage)
    {
        ShowInfoAndError("SqlCrud", $"Start {DateTime.Now:G}");
        var retVal = -2;
        databaseErrorMessage = string.Empty;
        using (var sqlConnection = new SqlConnection(connectionString))
        {
            using var sqlCommand = new SqlCommand(sql, sqlConnection);
            sqlCommand.CommandType = ctCommandType;
            if (sqlParameters != null) sqlCommand.Parameters.AddRange(sqlParameters.ToArray());
            for (var tries = 1; tries <= DatabaseRetries; tries++)
            {
                if (tries > 1)
                {
                    ShowInfoAndError("SqlCrud",
                        $"Transient error encountered during connection. Will begin attempt number {tries} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {databaseErrorMessage}");
                    Thread.Sleep(CleanInt(DatabaseRetryInterval * 1000 * Math.Pow(2, tries - 1)));
                }
                else
                {
                    ShowInfoAndError("SqlCrud",
                        $"Initial connection. Number {tries} of {DatabaseRetries} max... {GetSqlCallData(connectionString, sql, sqlParameters)}. {databaseErrorMessage}");
                }

                try
                {
                    if (sqlConnection.State != ConnectionState.Open) sqlConnection.OpenSqlConnection();
                    retVal = sqlCommand.ExecuteNonQuery();
                    databaseErrorMessage = string.Empty;
                    sqlCommand.Parameters.Clear();
                    break;
                }
                catch (SqlException ex)
                {
                    databaseErrorMessage = GetSqlException(sql, ex);
                }
                catch (Exception ex)
                {
                    databaseErrorMessage = GetStandardException(ex);
                }
            }

            sqlCommand.Parameters.Clear();
        }

        if (retVal == 0)
            retVal = -1;
        else
            retVal = 0;
        ShowInfoAndError("SqlCrud", $"Return. Error Message: {databaseErrorMessage}. Result: {retVal}.");
        return retVal;
    }

    public static bool IsDataSetEmpty(DataSet dsInput)
    {
        return dsInput == null || dsInput.Tables.Count == 0 || dsInput.Tables[0].Rows.Count == 0;
    }

    public static string GetSqlCallData(string connectionString, string sql, List<SqlParameter> sqlParameters)
    {
        var reVal = connectionString + Environment.NewLine;
        reVal += sql + Environment.NewLine;
        if (sqlParameters != null)
            foreach (var sqlParameter in sqlParameters)
                reVal += $"{sqlParameter.ParameterName}: {sqlParameter.Value} {Environment.NewLine}";
        reVal += Environment.NewLine;
        return reVal;
    }

    public static string GetSqlException(string sql, SqlException ex)
    {
        var retVal = $"SQL Error(s) Executing SQL Command \"{sql}\". {Environment.NewLine}";
        for (var i = 1; i < ex.Errors.Count + 1; i++)
            retVal +=
                $"SQL Error # {i} of {ex.Errors.Count}. Message: {ex.Errors[i - 1].Message}. Line Number: {ex.Errors[i - 1].LineNumber}. Source: {ex.Errors[i - 1].Source}. Procedure: {ex.Errors[i - 1].Procedure}. Error Number: {ex.Errors[i - 1].Number}." +
                Environment.NewLine;
        return retVal;
    }

    public static string GetStandardException(Exception ex)
    {
        return $"Error Message: {ex.Message}. Source: {ex.Source}. Stack Trace: {ex.StackTrace}. Data: {ex.Data}." +
               Environment.NewLine;
    }

    public static string GetPollyException(string sql, Exception ex)
    {
        if (ex is SqlException sqlException)
            return GetSqlException(sql, sqlException);
        if (ex != null) return GetStandardException(ex);
        return string.Empty;
    }

    public static void ShowPollySql(string functionName, TimeSpan timeLeft, int current, int total, string sql,
        Exception ex)
    {
        var pollyExceptionMessage = GetPollyException(sql, ex);
        ShowInfoAndError(functionName,
            $"SQL Error Encountered in \"{sql}\". {Environment.NewLine}Will try again in {timeLeft.TotalSeconds} second(s), {current} of {total} attempts... {Environment.NewLine}{pollyExceptionMessage}");
    }

    public static void ShowInfoAndError(string functionName, object input, bool isError = false)
    {
        if (AllowDebugMessage)
        {
            Debug.WriteLine(input is Exception exception
                ? $"Function {functionName} Error. {GetStandardException(exception)}"
                : $"Function {functionName} Info. {input as string}");
        }

        if (AllowLogMessage)
        {
            if (isError)
            {
                ApplicationLog.LogError(
                    input is Exception exception
                        ? $"Function {functionName} Error. {GetStandardException(exception)}"
                        : $"Function {functionName} Error. {input as string}");
            }
            else
            {
                ApplicationLog.LogInformation(
                    input is Exception exception
                        ? $"Function {functionName} Info. {GetStandardException(exception)}"
                        : $"Function {functionName} Info. {input as string}");
            }
        }
    }

    public static string GetScreenOutputText(object input)
    {
        var tempInput = CleanText(input);
        if (string.IsNullOrEmpty(tempInput)) return string.Empty;
        return (tempInput + Environment.NewLine).Replace(Environment.NewLine, "<br />" + Environment.NewLine);
    }

    public static bool IsExceptionCancellable(Exception ex)
    {
        if (ex is SqlException sqlException) return DatabaseCancellableErrors.Contains(sqlException.Number);
        return false;
    }

    public static bool IsDevMachine()
    {
        var enableDeveloperMachineCheck = ConfigurationManager.AppSettings["EnableDeveloperMachineCheck"];
        if (!string.IsNullOrEmpty(enableDeveloperMachineCheck))
        {
            var isCheckDeveloperMachine = CleanBit(enableDeveloperMachineCheck);
            return isCheckDeveloperMachine && Debugger.IsAttached;
        }
        return Debugger.IsAttached;
    }

    public static string GetCurrentUserDomainLogonNoEscape()
    {
        var userLogon = HttpContext.Current.User.Identity.Name.ToLower().Trim();
        if (string.IsNullOrEmpty(userLogon)) userLogon = WindowsIdentity.GetCurrent().Name.ToLower().Trim();
        return userLogon;
    }

    public static string GetCurrentUserDomainLogon()
    {
        return GetCurrentUserDomainLogonNoEscape().Replace("\\", "/");
    }

    public static string TrimLongString(string input, int maxlength)
    {
        var tempInput = CleanText(input);
        return tempInput.Length < maxlength ? tempInput : CleanText(tempInput.Substring(0, maxlength));
    }

    public static string EscapeQuoteTextForSql(object input)
    {
        return CleanText(CleanText(input).Replace("''", "'").Replace("''", "'").Replace("'", "''"));
    }

    public static string RemoveAposFromText(object input)
    {
        return CleanText(input).Replace("'", string.Empty);
    }

    public static string CleanNumber(string input)
    {
        if (string.IsNullOrEmpty(input)) return "0";
        var sb = new StringBuilder(input.Length);
        foreach (var c in input.Where(c => c == '.' || c == '-' || char.IsDigit(c)))
            sb.Append(c);
        return sb.ToString();
    }

    public static string CleanText(object input)
    {
        var retVal = string.Empty;
        switch (input)
        {
            case null:
                return retVal;
            case string s:
                retVal = s.Trim();
                break;
            default:
                retVal = input.ToString().Trim();
                break;
        }

        return retVal;
    }

    public static int CleanInt(object input)
    {
        var retVal = 0;
        if (input == null) return retVal;
        if (input is int i)
        {
            retVal = i;
        }
        else
        {
            var tempInput = CleanNumber(input.ToString());
            if (string.IsNullOrEmpty(tempInput)) return retVal;
            retVal = (int)CleanDecimal(tempInput, 0);
        }

        return retVal;
    }

    public static bool CleanBit(object input)
    {
        var retVal = false;
        if (input == null) return retVal;
        if (input is bool b)
        {
            retVal = b;
        }
        else
        {
            var tempInput = CleanText(input).ToUpper();
            if (string.IsNullOrEmpty(tempInput)) return retVal;
            retVal = tempInput.Equals("TRUE", StringComparison.CurrentCultureIgnoreCase) || tempInput.Equals("1");
        }

        return retVal;
    }

    public static DateTime CleanDate(object input)
    {
        var retVal = DateTime.MinValue;
        if (input == null) return retVal;
        if (input is DateTime time)
        {
            retVal = time;
        }
        else
        {
            var tempInput = CleanText(input);
            if (string.IsNullOrEmpty(tempInput)) return retVal;
            DateTime.TryParse(tempInput, out retVal);
        }

        return retVal;
    }

    public static string CleanShortDateString(object input)
    {
        return CleanDate(input).ToLocalTime().ToShortDateString();
    }

    public static DateTime ParseIso8601(string iso8601String)
    {
        return DateTimeOffset.Parse(iso8601String).UtcDateTime;
    }

    public static DateTime UtcTimeToUsPacificTime(DateTime utcTime)
    {
        // Don't be fooled - this really is the Pacific time zone, not just standard time...
        var timeZoneUsPacific = TimeZoneInfo.FindSystemTimeZoneById(UsPacificTimeZoneLookupName);
        return TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utcTime, DateTimeKind.Unspecified),
            timeZoneUsPacific);
    }

    public static decimal CleanDecimal(object input, int precision = PrecisionMoney)
    {
        decimal retVal = 0;
        if (input != null)
        {
            if (input is decimal input1)
            {
                retVal = input1;
            }
            else
            {
                var tempInput = CleanNumber(input.ToString());
                if (!string.IsNullOrEmpty(tempInput)) decimal.TryParse(tempInput, out retVal);
            }
        }

        retVal = Math.Round(retVal, precision, MidpointRounding.AwayFromZero);
        return retVal;
    }

    public static string CleanBluetoothAddress(string input)
    {
        if (string.IsNullOrEmpty(input)) return string.Empty;
        var sb = new StringBuilder(input.Length);
        foreach (var c in input)
            if (char.IsLetterOrDigit(c))
                sb.Append(c);
        return CleanText(sb.ToString().ToUpper());
    }

    public static bool ValidateBluetoothAddress(string input)
    {
        if (string.IsNullOrEmpty(input)) return false;
        return CleanBluetoothAddress(input).Length == StandardBluetoothAddressLength;
    }

    public static bool ValidateEmail(string email)
    {
        try
        {
            var address = new MailAddress(email);
            return address.Address.Equals(email, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static string GetCurrentSiteBaseUrl()
    {
        var request = HttpContext.Current.Request;
        return request.Url.Scheme + "://" + request.Url.Authority + request.ApplicationPath?.TrimEnd('/') + "/";
    }

    public static string GetCurrentUserIpAddress()
    {
        var request = HttpContext.Current.Request;
        var ipList = request.ServerVariables["HTTP_X_FORWARDED_FOR"];
        if (!string.IsNullOrEmpty(ipList)) return ipList.Split(',')[0];
        return request.ServerVariables["REMOTE_ADDR"];
    }

    public static void MessageBox(string textToShow, string redirectUrl = null)
    {
        if (string.IsNullOrEmpty(redirectUrl))
            HttpContext.Current.Response.Write("<script language =javascript > alert('" + textToShow + "');</script>");
        else
            HttpContext.Current.Response.Write("<script language =javascript > if (confirm('" + textToShow +
                                               "')) { window.location='" + redirectUrl + "'; } else { } ;</script>");
    }

    public static bool SetSelectedValue(DropDownList input, string selectedValue)
    {
        input.ClearSelection();
        var selectedListItem = input.Items.FindByValue(selectedValue);
        if (selectedListItem == null) return false;
        selectedListItem.Selected = true;
        return true;
    }

    public static bool SetSelectedValue(ListBox input, string selectedValue)
    {
        input.ClearSelection();
        var selectedListItem = input.Items.FindByValue(selectedValue);
        if (selectedListItem == null) return false;
        selectedListItem.Selected = true;
        return true;
    }

    public static string GetMd5HashedString(string input)
    {
        var tempInput = CleanText(input);
        if (string.IsNullOrEmpty(tempInput)) return string.Empty;
        var md5Algorithm = MD5.Create();
        var binaryData = md5Algorithm.ComputeHash(Encoding.UTF8.GetBytes(tempInput));
        var md5Value = new StringBuilder();
        foreach (var b in binaryData) md5Value.Append(b.ToString("x2").ToUpperInvariant());
        return md5Value.ToString();
    }

    public static string FormatPrice(decimal price, string symbol, bool intOnly = false)
    {
        var format = intOnly ? "{0:N0}" : "{0:N}";
        return symbol + string.Format(format, price);
    }

    public static string GenerateRandomKey(int length)
    {
        var allowedChars = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        var retValue = new StringBuilder();
        var allowedMax = allowedChars.Length;
        var rnd = new Random();
        for (var i = 0; i < length; i++) retValue.Append(allowedChars[rnd.Next(allowedMax)]);
        return retValue.ToString();
    }

    public static void EmailAddRecipients(MailAddressCollection messageTo, object allEmails)
    {
        if (allEmails != null)
        {
            var emails = allEmails.GetType().IsArray
                ? (string[])allEmails
                : ((string)allEmails).Split(new[] { ";," }, StringSplitOptions.None);

            foreach (var email in emails)
                if (ValidateEmail(email))
                    messageTo.Add(new MailAddress(email.Trim()));
        }
    }

    public static async Task<SendEmailResult> SmtpClientSendEmailAsync(string smtpServer, int smtpPort,
        string smtpAccount, string smtpPassword, string fromEmail, object toEmail, object ccEmail, object bccEmail,
        string subject, string htmlBody)
    {
        var sendEmailResult = new SendEmailResult { Result = false, ErrorMessage = string.Empty };
        var client = new SmtpClient(smtpServer, smtpPort)
        {
            UseDefaultCredentials = false,
            Credentials = new NetworkCredential(smtpAccount, smtpPassword),
            DeliveryMethod = SmtpDeliveryMethod.Network,
            EnableSsl = smtpPort != 25
        };
        var message = new MailMessage
        {
            From = new MailAddress(fromEmail),
            Subject = subject,
            Body = htmlBody + Environment.NewLine + Environment.NewLine,
            BodyEncoding = Encoding.UTF8,
            IsBodyHtml = true
        };
        if (IsDevMachine())
        {
            EmailAddRecipients(message.To, DeveloperEmailAddress);
        }
        else
        {
            EmailAddRecipients(message.To, toEmail);
            EmailAddRecipients(message.CC, ccEmail);
            EmailAddRecipients(message.Bcc, bccEmail);
        }

        try
        {
            await client.SendMailAsync(message);
            sendEmailResult.Result = true;
        }
        catch (SmtpException e)
        {
            var statusCode = e.StatusCode;
            if (statusCode == SmtpStatusCode.MailboxBusy || statusCode == SmtpStatusCode.MailboxUnavailable ||
                statusCode == SmtpStatusCode.TransactionFailed)
            {
                // wait 5 seconds, try a second time
                Thread.Sleep(5000);
                await SmtpClientSendEmailAsync(smtpServer, smtpPort, smtpAccount, smtpPassword, fromEmail, toEmail,
                    ccEmail, bccEmail, subject, htmlBody);
            }
            else
            {
                sendEmailResult.ErrorMessage =
                    $"Email From {fromEmail} with subject {subject} Failed. Error: {GetStandardException(e)}";
            }
        }
        catch (Exception e)
        {
            sendEmailResult.ErrorMessage =
                $"Email From {fromEmail} with subject {subject} Failed. Error: {GetStandardException(e)}";
        }
        finally
        {
            message.Dispose();
        }

        return sendEmailResult;
    }

    public static List<PropertyInformation> ObjectPropertyInformation(object inputObject)
    {
        if (inputObject == null) return null;
        var propertyInformation = new List<PropertyInformation>();

        foreach (var objectProperty in inputObject.GetType().GetProperties())
            // Skip Schema
            if (objectProperty.PropertyType == typeof(JSchema))
            {
                ShowInfoAndError("ObjectPropertyInformation",
                    objectProperty.Name + " Schema - skipped for Type " + objectProperty.PropertyType.Name);
            }
            //for value types
            else if (objectProperty.PropertyType.IsPrimitive || objectProperty.PropertyType.IsValueType ||
                     objectProperty.PropertyType == typeof(string))
            {
                ShowInfoAndError("ObjectPropertyInformation", objectProperty.Name + " Value");
                propertyInformation.Add(new PropertyInformation
                {
                    Name = objectProperty.Name,
                    Value = objectProperty.GetValue(inputObject),
                    IsDateTime = objectProperty.PropertyType == typeof(DateTime)
                });
            }
            //for complex types
            else if (objectProperty.PropertyType.IsClass &&
                     !typeof(IEnumerable).IsAssignableFrom(objectProperty.PropertyType))
            {
                if (objectProperty.GetValue(inputObject) != null)
                {
                    ShowInfoAndError("ObjectPropertyInformation", objectProperty.Name + " Complex");
                    propertyInformation.AddRange(ObjectPropertyInformation(objectProperty.GetValue(inputObject)));
                }
            }
            //for Enumerable
            else
            {
                ShowInfoAndError("ObjectPropertyInformation", objectProperty.Name + " Enumerable");
                if (objectProperty.GetValue(inputObject) is not IEnumerable enumerablePropObject) continue;
                var objList = enumerablePropObject.GetEnumerator();
                while (objList.MoveNext())
                {
                    propertyInformation.AddRange(ObjectPropertyInformation(objList.Current));
                    objList.MoveNext();
                }
            }

        return propertyInformation;
    }

    public static async Task<string> GetServiceAsync(string url, string userName = null, string password = null)
    {
        ShowInfoAndError("GetServiceAsync", $"Begin with Url {url}");
        try
        {
            var hch = new HttpClientHandler
            {
                Proxy = null,
                UseProxy = false
            };
            var httpClient = new HttpClient(hch);
            if (!string.IsNullOrEmpty(userName))
            {
                var authToken = Encoding.ASCII.GetBytes($"{userName}:{password}");
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(authToken));
                ShowInfoAndError("GetServiceAsync", "Added authToken with userName: " + userName);
            }
            ShowInfoAndError("GetServiceAsync", "Ready to GET");
            var response = await httpClient.GetAsync(url);
            ShowInfoAndError("GetServiceAsync", $"Finished GET with status code {response.StatusCode}");
            if (!response.IsSuccessStatusCode)
            {
                ShowInfoAndError("GetServiceAsync", $"Returning empty, Address not reachable: {url}");
                return string.Empty;
            }
            using var stream = await response.Content.ReadAsStreamAsync();
            using var streamReader = new StreamReader(stream);
            ShowInfoAndError("GetServiceAsync", "Returning ResponseContent as string.");
            return await streamReader.ReadToEndAsync();
        }
        catch (WebException e)
        {
            ShowInfoAndError("GetServiceAsync", $"Returning error: {GetStandardException(e)}. URL: {url}");
            if (e.Response != null)
                ShowInfoAndError("GetServiceAsync",
                    $"Response: {await new StreamReader(e.Response.GetResponseStream()!).ReadToEndAsync()}");
            return string.Empty;
        }
    }

    public static async Task<string> PostServiceAsync(string url, string content, string userName = null,
        string password = null)
    {
        ShowInfoAndError("PostServiceAsync", "Begin ");
        try
        {
            var buffer = Encoding.UTF8.GetBytes(content);
            var byteContent = new ByteArrayContent(buffer);
            byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var httpClient = new HttpClient();
            if (!string.IsNullOrEmpty(userName))
            {
                var authToken = Encoding.ASCII.GetBytes($"{userName}:{password}");
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(authToken));
                ShowInfoAndError("PostServiceAsync", "Added authToken with userName: " + userName);
            }

            var response = await httpClient.PostAsync(url, byteContent).ConfigureAwait(false);
            var result = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                ShowInfoAndError("PostServiceAsync",
                    "Returning wrong Status Code: " + response.StatusCode + ". Response: " + result);
                return string.Empty;
            }
            ShowInfoAndError("PostServiceAsync", "Reading Empty, return with result empty");
            return string.Empty;
        }
        catch (WebException e)
        {
            ShowInfoAndError("PostServiceAsync", $"Returning error: {GetStandardException(e)}. URL: {url}");
            if (e.Response != null)
                ShowInfoAndError("PostServiceAsync",
                    $"Response: {await new StreamReader(e.Response.GetResponseStream()!).ReadToEndAsync()}");
            return string.Empty;
        }
    }

    public static async Task<string> PutServiceAsync(string url, string content, string userName = null,
        string password = null)
    {
        ShowInfoAndError("PutServiceAsync", "Begin ");
        try
        {
            var buffer = Encoding.UTF8.GetBytes(content);
            var byteContent = new ByteArrayContent(buffer);
            byteContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var httpClient = new HttpClient();
            if (!string.IsNullOrEmpty(userName))
            {
                var authToken = Encoding.ASCII.GetBytes($"{userName}:{password}");
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(authToken));
                ShowInfoAndError("PutServiceAsync", "Added authToken with userName: " + userName);
            }

            var response = await httpClient.PutAsync(url, byteContent).ConfigureAwait(false);
            var result = await response.Content.ReadAsStringAsync();
            if (!response.IsSuccessStatusCode)
            {
                ShowInfoAndError("PutServiceAsync",
                    "Returning wrong Status Code: " + response.StatusCode + ". Response: " + result);
                return string.Empty;
            }
            ShowInfoAndError("PutServiceAsync", "Returning ResponseContent as string.");
            return result;
        }
        catch (WebException e)
        {
            ShowInfoAndError("PutServiceAsync", $"Returning error: {GetStandardException(e)}. URL: {url}");
            if (e.Response != null)
                ShowInfoAndError("PutServiceAsync",
                    $"Response: {await new StreamReader(e.Response.GetResponseStream()!).ReadToEndAsync()}");
            return string.Empty;
        }
    }

    public static async Task<bool> DeleteServiceAsync(string url, string userName = null, string password = null)
    {
        ShowInfoAndError("DeleteServiceAsync", $"Begin with Url {url}");
        try
        {
            var hch = new HttpClientHandler
            {
                Proxy = null,
                UseProxy = false
            };
            var httpClient = new HttpClient(hch);
            if (!string.IsNullOrEmpty(userName))
            {
                var authToken = Encoding.ASCII.GetBytes($"{userName}:{password}");
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic",
                    Convert.ToBase64String(authToken));
                ShowInfoAndError("DeleteServiceAsync", "Added authToken with userName: " + userName);
            }

            ShowInfoAndError("DeleteServiceAsync", "Ready to DELETE");
            var response = await httpClient.DeleteAsync(url);
            ShowInfoAndError("DeleteServiceAsync", $"Finished DELETE with status code {response.StatusCode}");
            if (!response.IsSuccessStatusCode)
            {
                ShowInfoAndError("DeleteServiceAsync", $"Returning false, Address not reachable: {url}");
                return false;
            }
            ShowInfoAndError("DeleteServiceAsync", $"Returning true, Address: {url}");
            return false;
        }
        catch (WebException e)
        {
            ShowInfoAndError("DeleteServiceAsync", $"Returning error: {GetStandardException(e)}. URL: {url}");
            if (e.Response != null)
                ShowInfoAndError("DeleteServiceAsync",
                    $"Response: {await new StreamReader(e.Response.GetResponseStream()!).ReadToEndAsync()}");
            return false;
        }
    }

    public static string StripJsonFromName(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        return CleanText(Regex.Replace(input.Trim(), ".json", string.Empty, RegexOptions.IgnoreCase));
    }

    public static string AddJsonToName(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;
        return CleanText(input) + ".json";
    }

    public static string GetPrettyJson(string unPrettyJson)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        var jsonElement = JsonSerializer.Deserialize<JsonElement>(unPrettyJson);
        return JsonSerializer.Serialize(jsonElement, options);
    }

    public static string GetEnumNameFromValue(object input)
    {
        try
        {
            return Enum.GetName(input.GetType(), input);
        }
        catch
        {
            return string.Empty;
        }
    }

    public static string ReplaceParameterInString(string input, string lookFor, string replaceWith)
    {
        var tempInput = CleanText(input);
        if (string.IsNullOrEmpty(tempInput)) return string.Empty;
        return input.Replace(lookFor, replaceWith);
    }

    public class SendEmailResult
    {
        public bool Result { get; set; }
        public string ErrorMessage { get; set; }
    }

    public class PropertyInformation
    {
        public string Name { get; set; }
        public object Value { get; set; }
        public bool IsDateTime { get; set; }
    }
}