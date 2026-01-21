export interface UserRow {
    id: string;
    username: string;
    display_name: string;
    avatar: string | null;
    created_at: Date;
    password_hash: string;
    deleted_at: Date | null;
}

export interface PoopLogRow {
    id: string;
    user_id: string;
    timestamp: Date;
    notes: string | null;
    latitude: number | null;
    longitude: number | null;
    location_name: string | null;
    photo_url: string | null;
    rating: number | null;
    duration_minutes: number | null;
    username?: string;
    display_name?: string;
}

export interface FriendshipRow {
    id: string;
    user_id: string;
    friend_id: string;
    status: 'pending' | 'accepted';
    created_at: Date;
    username?: string;
    display_name?: string;
    today_count?: string | number;
    week_count?: string | number;
}

export interface PublicUser {
    id: string;
    username: string;
    displayName: string;
}

export interface Stats {
    today: number;
    week: number;
    month: number;
    allTime: number;
    currentStreak: number;
    longestStreak: number;
    avgPerDay: number;
    dailyData: Array<{ date: string | Date; count: number }>;
}

export interface LeaderboardEntry {
    rank: number;
    user: PublicUser;
    value: number;
    isCurrentUser: boolean;
}
