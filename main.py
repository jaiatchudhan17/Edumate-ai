#main.py
import streamlit as st
import os
from dotenv import load_dotenv
from src.agents.summarizer_agent import SummarizerAgent
from src.agents.flashcard_agent import FlashcardAgent
from src.agents.planner_agent import PlannerAgent
from src.agents.quiz_agent import QuizAgent
from src.agents.tracker_agent import TrackerAgent

# Load environment variables
load_dotenv()

# Page configuration
st.set_page_config(
    page_title="EduMate - AI Student Assistant",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional styling
st.markdown("""
    <style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Global styling */
    .main {
        font-family: 'Inter', sans-serif;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 8px 32px rgba(102, 126, 234, 0.3);
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: linear-gradient(90deg, #f8fafc 0%, #e2e8f0 100%);
        padding: 8px;
        border-radius: 12px;
        box-shadow: inset 0 2px 4px rgba(0,0,0,0.06);
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 55px;
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        border-radius: 10px;
        color: white;
        padding: 12px 20px;
        font-weight: 500;
        border: none;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(99, 102, 241, 0.2);
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(99, 102, 241, 0.3);
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #059669 0%, #0d9488 100%);
        box-shadow: 0 6px 20px rgba(5, 150, 105, 0.4);
    }

    /* Tab headers */
    .tab-header {
        background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #6366f1;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 16px rgba(0,0,0,0.08);
    }
    
    .tab-header h2 {
        color: #1e293b;
        margin-bottom: 0.5rem;
        font-weight: 600;
    }
    
    .tab-header p {
        color: #64748b;
        margin: 0;
        font-size: 1.1rem;
    }

    /* Upload section styling */
    .upload-section {
        background: linear-gradient(135deg, #fef7ff 0%, #f3e8ff 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border: 2px dashed #a855f7;
        margin-bottom: 1rem;
        transition: all 0.3s ease;
    }
    
    .upload-section:hover {
        border-color: #7c3aed;
        background: linear-gradient(135deg, #faf5ff 0%, #f3e8ff 100%);
    }

    /* Container styling */
    .summary-container, .quiz-question {
        background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        margin-bottom: 1rem;
        box-shadow: 0 4px 16px rgba(0,0,0,0.06);
    }

    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #059669 0%, #0d9488 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.75rem 1.5rem;
        font-weight: 500;
        transition: all 0.3s ease;
        box-shadow: 0 4px 12px rgba(5, 150, 105, 0.2);
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #047857 0%, #0f766e 100%);
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(5, 150, 105, 0.3);
    }

    /* Input field styling */
    .stTextInput > div > div > input,
    .stTextArea > div > div > textarea,
    .stSelectbox > div > div > select {
        border: 2px solid #e2e8f0;
        border-radius: 8px;
        transition: all 0.3s ease;
    }
    
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus,
    .stSelectbox > div > div > select:focus {
        border-color: #6366f1;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
    }

    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #f1f5f9 0%, #e2e8f0 100%);
    }

    /* Success/Error message styling */
    .stSuccess {
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        border-left: 4px solid #059669;
    }
    
    .stError {
        background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%);
        border-left: 4px solid #dc2626;
    }
    
    .stInfo {
        background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%);
        border-left: 4px solid #2563eb;
    }
    
    .stWarning {
        background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
        border-left: 4px solid #d97706;
    }

    /* Quiz results styling */
    .quiz-results {
        background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #0284c7;
        margin: 1rem 0;
        box-shadow: 0 4px 16px rgba(2, 132, 199, 0.1);
    }

    /* Expander styling */
    .streamlit-expanderHeader {
        background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
        border-radius: 8px;
    }
    </style>
""", unsafe_allow_html=True)

def main():
    # Main header
    st.markdown("<h1 class='main-header'>🎓 EduMate - AI Student Assistant</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #64748b; font-size: 1.2rem; margin-bottom: 2rem;'>Your personalized AI companion for academic success</p>", unsafe_allow_html=True)
    
    # Create tabs - Removed "Coming Soon" tab
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📅 Study Planner", 
        "🃏 Flashcard Generator", 
        "📄 Document Summarizer", 
        "❓ Quiz Generator", 
        "🎯 Progress Tracker"
    ])
    
    with tab1:
        st.markdown("<div class='tab-header'><h2>📅 Study Planner</h2><p>Create personalized study plans based on your goals and schedule</p></div>", unsafe_allow_html=True)
        
        # Create two columns for layout
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.markdown("### Learning Goals & Preferences")
            
            # Topic/Goal input
            learning_topic = st.text_input(
                "📚 Learning Topic/Goal",
                placeholder="e.g., Data Science, AI, Machine Learning, Web Development",
                help="Enter what you want to learn"
            )
            
            # Duration selection
            study_duration = st.selectbox(
                "⏱️ Study Plan Duration",
                ["1 Week", "2 Weeks", "1 Month", "3 Months", "6 Months"],
                index=2,
                help="How long do you want your study plan to be?"
            )
            
            # Daily time input
            daily_study_time = st.selectbox(
                "🕐 Daily Study Time Available",
                ["30 minutes", "1 hour", "2 hours", "3 hours", "4+ hours"],
                index=1,
                help="How much time can you dedicate to studying each day?"
            )
            
            # Current level
            current_level = st.selectbox(
                "🎯 Current Knowledge Level",
                ["Beginner", "Intermediate", "Advanced"],
                help="What's your current level in this topic?"
            )
            
            # Learning style
            learning_style = st.selectbox(
                "📖 Preferred Learning Style",
                ["Theory-focused", "Hands-on/Project-based", "Mixed approach"],
                index=2,
                help="How do you prefer to learn?"
            )
            
            # Generate plan button
            generate_plan_btn = st.button("🚀 Create Study Plan", type="primary", use_container_width=True)
        
        with col2:
            st.markdown("### Your Personalized Study Plan")
            
            # Study plan display container
            plan_container = st.container()
            
            if learning_topic:
                # Display plan settings
                plan_settings = {
                    "Topic": learning_topic,
                    "Duration": study_duration,
                    "Daily Time": daily_study_time,
                    "Level": current_level,
                    "Style": learning_style
                }
                
                with st.expander("📋 Plan Settings"):
                    for key, value in plan_settings.items():
                        st.write(f"**{key}:** {value}")
                
                # Process and display study plan
                if 'generate_plan_btn' in locals() and generate_plan_btn:
                    try:
                        with st.spinner("🔄 Creating your personalized study plan..."):
                            # Initialize planner agent
                            planner = PlannerAgent()
                            
                            # Generate study plan
                            study_plan = planner.create_study_plan(
                                learning_topic,
                                study_duration,
                                daily_study_time,
                                current_level,
                                learning_style
                            )
                            
                            # Store the study plan in session state for tracker
                            st.session_state.current_study_plan = study_plan
                            st.session_state.plan_duration = study_duration
                            st.session_state.plan_topic = learning_topic
                            
                            # Display study plan
                            with plan_container:
                                st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                                st.markdown("#### 📅 Your Study Plan")
                                st.markdown(study_plan)
                                st.markdown("</div>", unsafe_allow_html=True)
                                
                                # Info about progress tracking
                                st.info("🎯 Your study plan has been saved! You can now track your progress in the 'Progress Tracker' tab.")
                                
                                # Download button
                                st.download_button(
                                    label="💾 Download Study Plan",
                                    data=study_plan,
                                    file_name=f"study_plan_{learning_topic.replace(' ', '_')}.txt",
                                    mime="text/plain"
                                )
                                
                    except Exception as e:
                        st.error(f"❌ Error creating study plan: {str(e)}")
                        st.info("Please try again or contact support if the issue persists.")
            
            else:
                with plan_container:
                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                    st.info("👆 Enter your learning topic to get started!")
                    st.markdown("**Examples:** Data Science, Machine Learning, Python Programming")
                    st.markdown("**Plan Features:** Daily breakdowns, Calendar view, Progress milestones")
                    st.markdown("**Personalized:** Based on your time, level, and learning style")
                    st.markdown("</div>", unsafe_allow_html=True)
    
    with tab2:
        st.markdown("<div class='tab-header'><h2>🃏 Flashcard Generator</h2><p>Transform your documents into study flashcards</p></div>", unsafe_allow_html=True)
        
        # Create two columns for layout
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.markdown("### Upload & Options")
            
            # File upload section
            with st.container():
                st.markdown("<div class='upload-section'>", unsafe_allow_html=True)
                flashcard_file = st.file_uploader(
                    "Choose a document for flashcards",
                    type=['pdf', 'docx'],
                    help="Upload PDF or DOCX files (max 10MB)",
                    key="flashcard_uploader"
                )
                st.markdown("</div>", unsafe_allow_html=True)
            
            # Flashcard options
            if flashcard_file:
                st.markdown("### Flashcard Options")
                
                num_cards = st.number_input(
                    "Number of Flashcards",
                    min_value=1,
                    max_value=50,
                    value=10,
                    help="How many flashcards do you want to generate?"
                )
                
                difficulty = st.selectbox(
                    "Difficulty Level",
                    ["Basic", "Intermediate", "Advanced"],
                    index=1,
                    help="Choose the complexity level for your flashcards"
                )
                
                st.markdown("### Study Options")
                
                shuffle_cards = st.checkbox(
                    "🔀 Shuffle flashcards",
                    help="Randomize the order of flashcards for better learning"
                )
                
                # Generate flashcards button
                generate_flashcards_btn = st.button("🃏 Generate Flashcards", type="primary", use_container_width=True)
        
        with col2:
            st.markdown("### Generated Flashcards")
            
            # Flashcards display container
            flashcards_container = st.container()
            
            if flashcard_file:
                # Display file info
                file_details = {
                    "Filename": flashcard_file.name,
                    "File Type": flashcard_file.type,
                    "File Size": f"{flashcard_file.size / 1024:.2f} KB"
                }
                
                with st.expander("📋 File Details"):
                    for key, value in file_details.items():
                        st.write(f"**{key}:** {value}")
                
                # Process and display flashcards
                if 'generate_flashcards_btn' in locals() and generate_flashcards_btn:
                    try:
                        with st.spinner("🔄 Processing document and generating flashcards..."):
                            # Initialize flashcard agent
                            flashcard_agent = FlashcardAgent()
                            
                            # Generate flashcards
                            flashcards = flashcard_agent.generate_flashcards(
                                flashcard_file, 
                                num_cards, 
                                difficulty, 
                                shuffle_cards
                            )
                            
                            # Display flashcards
                            with flashcards_container:
                                if flashcards:
                                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                                    
                                    # Display count and info
                                    st.success(f"✅ Generated {len(flashcards)} flashcards successfully!")
                                    
                                    # Display flashcards
                                    for i, card in enumerate(flashcards, 1):
                                        with st.container():
                                            st.markdown(f"### 🃏 Card {i}")
                                            st.markdown(f"**Term:** {card['term']}")
                                            st.markdown(f"**Definition:** {card['definition']}")
                                            st.markdown("---")
                                    
                                    st.markdown("</div>", unsafe_allow_html=True)
                                    
                                    # Download button
                                    print_format = flashcard_agent.format_flashcards_for_print(
                                        flashcards, 
                                        flashcard_file.name
                                    )
                                    
                                    st.download_button(
                                        label="🖨️ Download Print-Friendly Version",
                                        data=print_format,
                                        file_name=f"flashcards_{flashcard_file.name.split('.')[0]}.txt",
                                        mime="text/plain"
                                    )
                                else:
                                    st.warning("⚠️ No flashcards were generated. Please try with a different document.")
                                    
                    except Exception as e:
                        st.error(f"❌ Error generating flashcards: {str(e)}")
                        st.info("Please try uploading the document again or contact support if the issue persists.")
            
            else:
                with flashcards_container:
                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                    st.info("👆 Upload a document to generate flashcards!")
                    st.markdown("**Supported formats:** PDF, DOCX")
                    st.markdown("**Max file size:** 10MB")
                    st.markdown("**Features:** Term/Definition pairs, Multiple difficulty levels, Shuffle option")
                    st.markdown("</div>", unsafe_allow_html=True)
    
    with tab3:
        st.markdown("<div class='tab-header'><h2>📄 Document Summarizer</h2><p>Upload your documents and get intelligent summaries</p></div>", unsafe_allow_html=True)
        
        # Create two columns for layout
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.markdown("### Upload & Options")
            
            # File upload section
            with st.container():
                st.markdown("<div class='upload-section'>", unsafe_allow_html=True)
                uploaded_file = st.file_uploader(
                    "Choose a document",
                    type=['pdf', 'docx'],
                    help="Upload PDF or DOCX files (max 10MB)"
                )
                st.markdown("</div>", unsafe_allow_html=True)
            
            # Summary options
            if uploaded_file:
                st.markdown("### Summary Options")
                
                summary_length = st.selectbox(
                    "Summary Type",
                    ["Brief (3-5 key points)", "Detailed (7-10 key points)", "Comprehensive (10+ key points)"],
                    help="Choose the depth of summary you need"
                )
                
                focus_area = st.selectbox(
                    "Focus Area (Optional)",
                    ["General Overview", "Main Arguments", "Key Concepts", "Important Facts", "Conclusions"],
                    help="What aspect should the summary emphasize?"
                )
                
                # Generate summary button
                generate_btn = st.button("🚀 Generate Summary", type="primary", use_container_width=True)
        
        with col2:
            st.markdown("### Generated Summary")
            
            # Summary display container
            summary_container = st.container()
            
            if uploaded_file:
                # Display file info
                file_details = {
                    "Filename": uploaded_file.name,
                    "File Type": uploaded_file.type,
                    "File Size": f"{uploaded_file.size / 1024:.2f} KB"
                }
                
                with st.expander("📋 File Details"):
                    for key, value in file_details.items():
                        st.write(f"**{key}:** {value}")
                
                # Process and display summary
                if 'generate_btn' in locals() and generate_btn:
                    try:
                        with st.spinner("🔄 Processing document and generating summary..."):
                            # Initialize summarizer agent
                            summarizer = SummarizerAgent()
                            
                            # Generate summary
                            summary = summarizer.summarize_document(
                                uploaded_file, 
                                summary_length, 
                                focus_area
                            )
                            
                            # Display summary
                            with summary_container:
                                st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                                st.markdown("#### 📝 Summary")
                                st.markdown(summary)
                                st.markdown("</div>", unsafe_allow_html=True)
                                
                                # Download button
                                st.download_button(
                                    label="💾 Download Summary",
                                    data=summary,
                                    file_name=f"summary_{uploaded_file.name.split('.')[0]}.txt",
                                    mime="text/plain"
                                )
                                
                    except Exception as e:
                        st.error(f"❌ Error processing document: {str(e)}")
                        st.info("Please try uploading the document again or contact support if the issue persists.")
            
            else:
                with summary_container:
                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                    st.info("👆 Upload a document to get started!")
                    st.markdown("**Supported formats:** PDF, DOCX")
                    st.markdown("**Max file size:** 10MB")
                    st.markdown("</div>", unsafe_allow_html=True)
    
    with tab4:
        st.markdown("<div class='tab-header'><h2>❓ Quiz Generator</h2><p>Test your knowledge with AI-generated quizzes</p></div>", unsafe_allow_html=True)
        
        # Create two columns for layout
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.markdown("### Quiz Configuration")
            
            # Topic input
            quiz_topic = st.text_input(
                "📚 Quiz Topic",
                placeholder="e.g., Python Programming, Data Science, Machine Learning",
                help="Enter the topic you want to be quizzed on"
            )
            
            # Number of questions
            num_questions = st.number_input(
                "📝 Number of Questions",
                min_value=1,
                max_value=50,
                value=10,
                help="How many questions do you want in your quiz?"
            )
            
            # Difficulty level
            quiz_difficulty = st.selectbox(
                "🎯 Difficulty Level",
                ["Easy", "Intermediate", "Hard"],
                index=1,
                help="Choose the difficulty level for your quiz"
            )
            
            # Question types
            st.markdown("### Question Types")
            question_types = []
            
            if st.checkbox("Multiple Choice", value=True):
                question_types.append("Multiple Choice")
            if st.checkbox("True/False", value=True):
                question_types.append("True-False")
            
            if not question_types:
                st.warning("⚠️ Please select at least one question type")
            
            # Generate quiz button
            generate_quiz_btn = st.button("❓ Generate Quiz", type="primary", use_container_width=True, disabled=not question_types)
        
        with col2:
            st.markdown("### Quiz Interface")
            
            # Quiz display container
            quiz_container = st.container()
            
            if quiz_topic and question_types:
                # Display quiz settings
                quiz_settings = {
                    "Topic": quiz_topic,
                    "Questions": str(num_questions),
                    "Difficulty": quiz_difficulty,
                    "Types": ", ".join(question_types)
                }
                
                with st.expander("📋 Quiz Settings"):
                    for key, value in quiz_settings.items():
                        st.write(f"**{key}:** {value}")
                
                # Process and display quiz
                if 'generate_quiz_btn' in locals() and generate_quiz_btn:
                    try:
                        with st.spinner("🔄 Generating quiz questions..."):
                            # Initialize quiz agent
                            quiz_agent = QuizAgent()
                            
                            # Generate quiz questions
                            questions = quiz_agent.create_quiz(
                                quiz_topic,
                                num_questions,
                                quiz_difficulty,
                                question_types
                            )
                            
                            # Store questions in session state
                            st.session_state.current_quiz = questions
                            st.session_state.quiz_topic = quiz_topic
                    except Exception as e:
                        st.error(f"❌ Error generating quiz: {str(e)}")
                        st.info("Please try again or contact support if the issue persists.")
            
            # Display quiz if available
            if 'current_quiz' in st.session_state and st.session_state.current_quiz:
                with quiz_container:
                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                    st.success(f"✅ Generated {len(st.session_state.current_quiz)} questions successfully!")
                    
                    # Create form for quiz answers
                    with st.form("quiz_form"):
                        user_answers = {}
                        
                        for i, question in enumerate(st.session_state.current_quiz, 1):
                            st.markdown(f"<div class='quiz-question'>", unsafe_allow_html=True)
                            st.markdown(f"**Question {i}:** {question['question']}")
                            
                            if question['type'] == 'Multiple Choice' and question['options']:
                                # Extract options for radio buttons
                                options = [opt.split(')', 1)[1].strip() if ')' in opt else opt for opt in question['options']]
                                option_labels = ['A', 'B', 'C', 'D'][:len(options)]
                                
                                selected_option = st.radio(
                                    f"Select your answer for Question {i}:",
                                    options,
                                    key=f"q_{i}",
                                    index=None
                                )
                                
                                # Map selected option back to letter
                                if selected_option:
                                    selected_index = options.index(selected_option)
                                    user_answers[f"q_{i}"] = option_labels[selected_index]
                            
                            elif question['type'] == 'True-False':
                                selected_answer = st.radio(
                                    f"Select your answer for Question {i}:",
                                    ["True", "False"],
                                    key=f"q_{i}",
                                    index=None
                                )
                                if selected_answer:
                                    user_answers[f"q_{i}"] = selected_answer
                            
                            st.markdown("</div>", unsafe_allow_html=True)
                        
                        # Submit quiz button
                        submit_quiz = st.form_submit_button("📊 Submit Quiz", type="primary")
                        
                        if submit_quiz:
                            try:
                                # Calculate score
                                quiz_agent = QuizAgent()
                                score_data = quiz_agent.calculate_score(st.session_state.current_quiz, user_answers)
                                
                                # Save performance
                                quiz_agent.save_quiz_performance(st.session_state.quiz_topic, score_data)
                                
                                # Display results
                                st.markdown("<div class='quiz-results'>", unsafe_allow_html=True)
                                st.markdown("### 🎯 Quiz Results")
                                st.markdown(f"**Score:** {score_data['correct_answers']}/{score_data['total_questions']} ({score_data['score_percentage']:.1f}%)")
                                st.markdown(f"**Grade:** {score_data['grade']}")
                                st.markdown("</div>", unsafe_allow_html=True)
                                
                                # Show detailed results
                                with st.expander("📋 Detailed Results & Explanations"):
                                    for result in score_data['detailed_results']:
                                        status = "✅ Correct" if result['is_correct'] else "❌ Incorrect"
                                        st.markdown(f"**Q{result['question_num']}:** {result['question']}")
                                        st.markdown(f"{status} - Your answer: {result['user_answer']}")
                                        st.markdown(f"**Correct answer:** {result['correct_answer']}")
                                        st.markdown(f"**Explanation:** {result['explanation']}")
                                        st.markdown("---")
                                
                                # Download results
                                results_text = quiz_agent.format_quiz_results(st.session_state.quiz_topic, score_data)
                                st.download_button(
                                    label="💾 Download Results",
                                    data=results_text,
                                    file_name=f"quiz_results_{st.session_state.quiz_topic.replace(' ', '_')}.txt",
                                    mime="text/plain"
                                )
                            except Exception as e:
                                st.error(f"❌ Error processing quiz results: {str(e)}")
                                st.info("Please try submitting the quiz again or contact support if the issue persists.")
                    
                    st.markdown("</div>", unsafe_allow_html=True)
            
            elif quiz_topic:
                with quiz_container:
                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                    st.info("👆 Configure your quiz settings and click 'Generate Quiz' to start!")
                    st.markdown("**Features:** Multiple choice & True/False questions")
                    st.markdown("**Instant feedback:** Get explanations for all answers")
                    st.markdown("**Performance tracking:** View your quiz history")
                    st.markdown("</div>", unsafe_allow_html=True)
            
            else:
                with quiz_container:
                    st.markdown("<div class='summary-container'>", unsafe_allow_html=True)
                    st.info("👆 Enter a quiz topic to get started!")
                    st.markdown("**Examples:** Python basics, Machine Learning concepts, Data Analysis")
                    st.markdown("**Question types:** Multiple choice, True/False")
                    st.markdown("**Difficulty levels:** Easy, Intermediate, Hard")
                    st.markdown("</div>", unsafe_allow_html=True)
        
        # Quiz history section
        if st.checkbox("📊 Show Quiz History"):
            try:
                quiz_agent = QuizAgent()
                history = quiz_agent.get_quiz_history()
                
                if history:
                    st.markdown("### 📈 Your Quiz Performance History")
                    for i, record in enumerate(reversed(history[-10:]), 1):  # Show last 10 quizzes
                        st.markdown(f"**{i}.** {record['topic']} - {record['score_percentage']:.1f}% ({record['grade']}) - {record['date']}")
                else:
                    st.info("No quiz history available yet. Take your first quiz!")
            except Exception as e:
                st.error(f"❌ Error loading quiz history: {str(e)}")
    
    # NEW: Progress Tracker Tab
    with tab5:
        st.markdown("<div class='tab-header'><h2>🎯 Progress Tracker</h2><p>Monitor your learning journey and celebrate achievements</p></div>", unsafe_allow_html=True)
        
        try:
            # Initialize tracker agent
            tracker = TrackerAgent()
            
            # Display the tracker interface
            tracker.display_tracker_interface()
            
        except Exception as e:
            st.error(f"❌ Error loading progress tracker: {str(e)}")
            st.info("Please try refreshing the page or contact support if the issue persists.")
    
    

if __name__ == "__main__":
    main()